use std::{
    ffi::c_void,
    io::{self, Error},
    mem,
    net::{SocketAddrV4, UdpSocket},
    os::unix::{io::AsRawFd, prelude::RawFd},
    sync::Arc,
};

use clap::Parser;
use libc::SO_LOCK_FILTER;
use nix::libc::{
    c_int, setsockopt, sock_filter, sock_fprog, socklen_t, SOL_SOCKET, SO_ATTACH_FILTER,
};
use smol::Async;
use socket2::{Domain, Protocol, Type};
use wireguard::{get_listen_port, InterfaceName};

fn attach_filter(fd: RawFd, filter: &mut [sock_filter]) -> io::Result<()> {
    let filter = sock_fprog {
        len: filter.len().try_into().unwrap(),
        filter: filter.as_mut_ptr(),
    };

    // Safety. Take ownership of sock_fprog
    match unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_ATTACH_FILTER,
            &filter as *const _ as *const c_void,
            mem::size_of_val(&filter) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }?;

    match unsafe {
        let v: c_int = 1;
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_LOCK_FILTER,
            &v as *const _ as *const c_void,
            mem::size_of_val(&v) as socklen_t,
        )
    } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

const BPF_LD: u16 = 0x00;
const BPF_K: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_JEQ: u16 = 0x10;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_ABS: u16 = 0x20;
const BPF_W: u16 = 0x00;

fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        k,
        jf: 0,
        jt: 0,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, k, jt, jf }
}

#[derive(Debug)]
struct NatSocket(Arc<Async<UdpSocket>>);

impl NatSocket {
    pub fn new(listen_port: u16, server: SocketAddrV4) -> Result<Self, io::Error> {
        let socket: UdpSocket =
            socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?.into();

        apply_bpf(&socket, listen_port, &server)?;

        let socket = Async::new(socket)?;

        Ok(Self(Arc::new(socket)))
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(buf).await
    }
}

fn apply_bpf(socket: &UdpSocket, listen_port: u16, server: &SocketAddrV4) -> io::Result<()> {
    let mut bpf = [
        // Check source IP from IP header
        bpf_stmt(BPF_LD + BPF_W + BPF_ABS, 12),
        bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, server.ip().clone().into(), 0, 5),
        // Check source port from UDP header
        bpf_stmt(BPF_LD + BPF_ABS + BPF_H, 20),
        bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, server.port().into(), 0, 3),
        // Check destination port from UDP header
        bpf_stmt(BPF_LD + BPF_ABS + BPF_H, 22),
        bpf_jump(BPF_JMP + BPF_JEQ + BPF_K, listen_port.into(), 0, 1),
        bpf_stmt(BPF_RET + BPF_K, u32::MAX),
        bpf_stmt(BPF_RET + BPF_K, 0),
    ];

    attach_filter(socket.as_raw_fd(), &mut bpf)
}

#[derive(Parser)]
struct Cli {
    #[clap(long)]
    server: SocketAddrV4,

    #[clap(long)]
    interface: InterfaceName,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let (s, ctrl_c) = smol::channel::bounded(100);

    let handle = move || {
        s.try_send(()).ok();
    };

    ctrlc::set_handler(handle).unwrap();

    smol::block_on(async {
        println!("{:?}", cli.interface);
        let listen_port = get_listen_port(&cli.interface).await?;
        println!("{:?}", listen_port);
        let socket = NatSocket::new(listen_port, cli.server);

        println!("{:?}", socket);
        ctrl_c.recv().await.ok();

        Ok(())
    })
}
