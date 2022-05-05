use std::{io, net::SocketAddr};

use netlink::request::netlink_request_genl;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};

use crate::InterfaceName;

pub async fn get_listen_port(name: &InterfaceName) -> Result<u16, io::Error> {
    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(name.as_str_lossy().to_string())],
    });

    let responses =
        netlink_request_genl(genlmsg, Some(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK)).await?;

    let nlas = responses.into_iter().fold(Ok(vec![]), |nlas_res, nlmsg| {
        let mut nlas = nlas_res?;
        let mut message = match nlmsg {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(message),
                ..
            } => message,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected netlink payload: {:?}", nlmsg),
                ))
            }
        };

        nlas.append(&mut message.payload.nlas);
        Ok(nlas)
    })?;

    nlas.iter()
        .find_map(|attr| match attr {
            WgDeviceAttrs::ListenPort(v) => Some(v),
            _ => None,
        })
        .cloned()
        .ok_or(io::Error::new(
            io::ErrorKind::InvalidData,
            "No listen port recieved",
        ))
}
