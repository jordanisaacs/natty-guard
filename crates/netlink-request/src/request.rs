use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NETLINK_HEADER_LEN,
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    constants::GENL_HDRLEN,
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlMessage,
};
use netlink_sys::{constants::NETLINK_GENERIC, AsyncSocket, AsyncSocketExt, SmolSocket};
use std::{fmt::Debug, io};

pub const MAX_NETLINK_BUFFER_LENGTH: usize = 4096;
pub const MAX_GENL_PAYLOAD_LENGTH: usize =
    MAX_NETLINK_BUFFER_LENGTH - NETLINK_HEADER_LEN - GENL_HDRLEN;

pub async fn netlink_request_genl<F>(
    mut message: GenlMessage<F>,
    flags: Option<u16>,
) -> Result<Vec<NetlinkMessage<GenlMessage<F>>>, io::Error>
where
    F: GenlFamily + Clone + Debug + Eq,
    GenlMessage<F>: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    if message.family_id() == 0 {
        let genlmsg = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName(F::family_name().to_string())],
        });
        let responses = netlink_request::<GenlMessage<GenlCtrl>>(
            genlmsg,
            Some(NLM_F_REQUEST | NLM_F_ACK),
            NETLINK_GENERIC,
        )
        .await?;

        match responses.get(0) {
            Some(NetlinkMessage {
                payload:
                    NetlinkPayload::InnerMessage(GenlMessage {
                        payload: GenlCtrl { nlas, .. },
                        ..
                    }),
                ..
            }) => {
                let family_id = nlas
                    .iter()
                    .find_map(|a| match a {
                        GenlCtrlAttrs::FamilyId(v) => Some(v),
                        _ => None,
                    })
                    .ok_or_else(|| io::ErrorKind::NotFound)?;

                message.set_resolved_family_id(*family_id);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected netlink payload",
                ))
            }
        };
    }
    netlink_request(message, flags, NETLINK_GENERIC).await
}

pub async fn netlink_request<I>(
    message: I,
    flags: Option<u16>,
    proto: isize,
) -> Result<Vec<NetlinkMessage<I>>, io::Error>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);

    if req.buffer_len() > MAX_NETLINK_BUFFER_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Serialized netlink packet ({} bytes) larger than maximum size {}: {:?}",
                req.buffer_len(),
                MAX_NETLINK_BUFFER_LENGTH,
                req
            ),
        ));
    }

    req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    req.finalize();
    let mut buf = bytes::BytesMut::new();
    buf.resize(MAX_NETLINK_BUFFER_LENGTH, 0);
    req.serialize(&mut buf);
    let len = req.buffer_len();

    let mut socket = SmolSocket::new(proto)?;
    let kernel_addr = netlink_sys::SocketAddr::new(0, 0);
    socket.socket_ref().connect(&kernel_addr)?;
    let n_sent = socket.send(&buf[..len]).await?;
    if n_sent != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Failed to send entire netlink request: {}/{}", n_sent, len),
        ));
    }

    let mut responses = vec![];
    loop {
        buf.clear();
        socket.recv(&mut buf).await?;
        let mut offset = 0;
        loop {
            let bytes = &buf[offset..];
            let response = NetlinkMessage::<I>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            match response.payload {
                // We've parsed all parts of the response and can leave the loop.
                NetlinkPayload::Ack(_) | NetlinkPayload::Done => return Ok(responses),
                NetlinkPayload::Error(e) => return Err(e.into()),
                _ => {}
            }
            responses.push(response.clone());
            offset += response.header.length as usize;
            if offset == buf.len() || response.header.length == 0 {
                // We've fully parsed the datagram, but there may be further datagrams
                // with additional netlink response parts.
                break;
            }
        }
    }
}
