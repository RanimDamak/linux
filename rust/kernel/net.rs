// SPDX-License-Identifier: GPL-2.0

//! Networking core.
//!
//! C headers: [`include/net/net_namespace.h`](../../../../include/linux/net/net_namespace.h),
//! [`include/linux/netdevice.h`](../../../../include/linux/netdevice.h),
//! [`include/linux/skbuff.h`](../../../../include/linux/skbuff.h).

use crate::{bindings, str::CStr, to_result, ARef, AlwaysRefCounted, Error, Result};
use core::{cell::UnsafeCell, ptr::NonNull};

#[cfg(CONFIG_NETFILTER)]
pub mod filter;

/// Wraps the kernel's `struct net_device`.
#[repr(transparent)]
pub struct Device(UnsafeCell<bindings::net_device>);

// SAFETY: Instances of `Device` are created on the C side. They are always refcounted.
unsafe impl AlwaysRefCounted for Device {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference means that the refcount is nonzero.
        unsafe { bindings::dev_hold(self.0.get()) };
    }

    unsafe fn dec_ref(obj: core::ptr::NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is nonzero.
        unsafe { bindings::dev_put(obj.cast().as_ptr()) };
    }
}

/// Wraps the kernel's `struct net`.
#[repr(transparent)]
pub struct Namespace(UnsafeCell<bindings::net>);

impl Namespace {
    /// Finds a network device with the given name in the namespace.
    pub fn dev_get_by_name(&self, name: &CStr) -> Option<ARef<Device>> {
        // SAFETY: The existence of a shared reference guarantees the refcount is nonzero.
        let ptr =
            NonNull::new(unsafe { bindings::dev_get_by_name(self.0.get(), name.as_char_ptr()) })?;
        Some(unsafe { ARef::from_raw(ptr.cast()) })
    }
}

// SAFETY: Instances of `Namespace` are created on the C side. They are always refcounted.
unsafe impl AlwaysRefCounted for Namespace {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference means that the refcount is nonzero.
        unsafe { bindings::get_net(self.0.get()) };
    }

    unsafe fn dec_ref(obj: core::ptr::NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is nonzero.
        unsafe { bindings::put_net(obj.cast().as_ptr()) };
    }
}

/// Returns the network namespace for the `init` process.
pub fn init_ns() -> &'static Namespace {
    unsafe { &*core::ptr::addr_of!(bindings::init_net).cast() }
}

/// Wraps the kernel's `struct sk_buff`.
#[repr(transparent)]
pub struct SkBuff(UnsafeCell<bindings::sk_buff>);

impl SkBuff {
    /// Creates a reference to an [`SkBuff`] from a valid pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ptr` is valid and remains valid for the lifetime of the
    /// returned [`SkBuff`] instance.
    pub unsafe fn from_ptr<'a>(ptr: *const bindings::sk_buff) -> &'a SkBuff {
        // SAFETY: The safety requirements guarantee the validity of the dereference, while the
        // `SkBuff` type being transparent makes the cast ok.
        unsafe { &*ptr.cast() }
    }

    /// Returns the remaining data in the buffer's first segment.
    pub fn head_data(&self) -> &[u8] {
        // SAFETY: The existence of a shared reference means that the refcount is nonzero.
        let headlen = unsafe { bindings::skb_headlen(self.0.get()) };
        let len = headlen.try_into().unwrap_or(usize::MAX);
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        let data = unsafe { core::ptr::addr_of!((*self.0.get()).data).read() };
        // SAFETY: The `struct sk_buff` conventions guarantee that at least `skb_headlen(skb)` bytes
        // are valid from `skb->data`.
        unsafe { core::slice::from_raw_parts(data, len) }
    }

    /// Returns the total length of the data (in all segments) in the skb.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        // SAFETY: The existence of a shared reference means `self.0` is valid.
        unsafe { core::ptr::addr_of!((*self.0.get()).len).read() }
    }
}

// SAFETY: Instances of `SkBuff` are created on the C side. They are always refcounted.
unsafe impl AlwaysRefCounted for SkBuff {
    fn inc_ref(&self) {
        // SAFETY: The existence of a shared reference means that the refcount is nonzero.
        unsafe { bindings::skb_get(self.0.get()) };
    }

    unsafe fn dec_ref(obj: core::ptr::NonNull<Self>) {
        // SAFETY: The safety requirements guarantee that the refcount is nonzero.
        unsafe {
            bindings::kfree_skb_reason(
                obj.cast().as_ptr(),
                bindings::skb_drop_reason_SKB_DROP_REASON_NOT_SPECIFIED,
            )
        };
    }
}

/// An IPv4 address.
///
/// This is equivalent to C's `in_addr`.
#[repr(transparent)]
pub struct Ipv4Addr(bindings::in_addr);

impl Ipv4Addr {
    /// A wildcard IPv4 address.
    ///
    /// Binding to this address means binding to all IPv4 addresses.
    pub const ANY: Self = Self::new(0, 0, 0, 0);

    /// The IPv4 loopback address.
    pub const LOOPBACK: Self = Self::new(127, 0, 0, 1);

    /// The IPv4 broadcast address.
    pub const BROADCAST: Self = Self::new(255, 255, 255, 255);

    /// Creates a new IPv4 address with the given components.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(bindings::in_addr {
            s_addr: u32::from_be_bytes([a, b, c, d]).to_be(),
        })
    }
}

/// An IPv6 address.
///
/// This is equivalent to C's `in6_addr`.
#[repr(transparent)]
pub struct Ipv6Addr(bindings::in6_addr);

impl Ipv6Addr {
    /// A wildcard IPv6 address.
    ///
    /// Binding to this address means binding to all IPv6 addresses.
    pub const ANY: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 0);

    /// The IPv6 loopback address.
    pub const LOOPBACK: Self = Self::new(0, 0, 0, 0, 0, 0, 0, 1);

    /// Creates a new IPv6 address with the given components.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> Self {
        Self(bindings::in6_addr {
            in6_u: bindings::in6_addr__bindgen_ty_1 {
                u6_addr16: [
                    a.to_be(),
                    b.to_be(),
                    c.to_be(),
                    d.to_be(),
                    e.to_be(),
                    f.to_be(),
                    g.to_be(),
                    h.to_be(),
                ],
            },
        })
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Default)]
pub struct SocketAddrStorage(bindings::__kernel_sockaddr_storage);

/// A socket address.
///
/// It's an enum with either an IPv4 or IPv6 socket address.
pub enum SocketAddr {
    /// An IPv4 socket address.
    V4(SocketAddrV4),

    /// An IPv6 socket address.
    V6(SocketAddrV6),
}

impl SocketAddr {

    pub fn as_ptr(&self) -> *const SocketAddrStorage {
        match self {
            SocketAddr::V4(addr) => addr as *const _ as _,
            SocketAddr::V6(addr) => addr as *const _ as _,
        }
    }
    pub fn size(&self) -> usize {
        match self {
            SocketAddr::V4(_) => SocketAddrV4::size(),
            SocketAddr::V6(_) => SocketAddrV6::size(),
        }
    }

}

/// An IPv4 socket address.
///
/// This is equivalent to C's `sockaddr_in`.
#[repr(transparent)]
pub struct SocketAddrV4(bindings::sockaddr_in);

impl SocketAddrV4 {
    /// Creates a new IPv4 socket address.
    pub const fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self(bindings::sockaddr_in {
            sin_family: bindings::AF_INET as _,
            sin_port: port.to_be(),
            sin_addr: addr.0,
            __pad: [0; 8],
        })
    }
    pub fn size() -> usize
    where
        Self: Sized,
    {
        core::mem::size_of::<Self>()
    }
}

/// An IPv6 socket address.
///
/// This is equivalent to C's `sockaddr_in6`.
#[repr(transparent)]
pub struct SocketAddrV6(bindings::sockaddr_in6);

impl SocketAddrV6 {
    /// Creates a new IPv6 socket address.
    pub const fn new(addr: Ipv6Addr, port: u16, flowinfo: u32, scopeid: u32) -> Self {
        Self(bindings::sockaddr_in6 {
            sin6_family: bindings::AF_INET6 as _,
            sin6_port: port.to_be(),
            sin6_addr: addr.0,
            sin6_flowinfo: flowinfo,
            sin6_scope_id: scopeid,
        })
    }
    pub fn size() -> usize
    where
        Self: Sized,
    {
        core::mem::size_of::<Self>()
    }
}

/// A socket listening on a TCP port.
///
/// # Invariants
///
/// The socket pointer is always non-null and valid.
pub struct TcpListener {
    pub(crate) sock: *mut bindings::socket,
}

// SAFETY: `TcpListener` is just a wrapper for a kernel socket, which can be used from any thread.
unsafe impl Send for TcpListener {}

// SAFETY: `TcpListener` is just a wrapper for a kernel socket, which can be used from any thread.
unsafe impl Sync for TcpListener {}

impl TcpListener {
    /// Creates a new TCP listener.
    ///
    /// It is configured to listen on the given socket address for the given namespace.
    pub fn try_new(ns: &Namespace, addr: &SocketAddr) -> Result<Self> {
        let mut socket = core::ptr::null_mut();
        let (pf, addr, addrlen) = match addr {
            SocketAddr::V4(addr) => (
                bindings::PF_INET,
                addr as *const _ as _,
                core::mem::size_of::<bindings::sockaddr_in>(),
            ),
            SocketAddr::V6(addr) => (
                bindings::PF_INET6,
                addr as *const _ as _,
                core::mem::size_of::<bindings::sockaddr_in6>(),
            ),
        };

        // SAFETY: The namespace is valid and the output socket pointer is valid for write.
        to_result(unsafe {
            bindings::sock_create_kern(
                ns.0.get(),
                pf as _,
                bindings::sock_type_SOCK_STREAM as _,
                bindings::IPPROTO_TCP as _,
                &mut socket,
            )
        })?;

        // INVARIANT: The socket was just created, so it is valid.
        let listener = Self { sock: socket };

        // SAFETY: The type invariant guarantees that the socket is valid, and `addr` and `addrlen`
        // were initialised based on valid values provided in the address enum.
        to_result(unsafe { bindings::kernel_bind(socket, addr, addrlen as _) })?;

        // SAFETY: The socket is valid per the type invariant.
        to_result(unsafe { bindings::kernel_listen(socket, bindings::SOMAXCONN as _) })?;

        Ok(listener)
    }

    /// Accepts a new connection.
    ///
    /// On success, returns the newly-accepted socket stream.
    ///
    /// If no connection is available to be accepted, one of two behaviours will occur:
    /// - If `block` is `false`, returns [`crate::error::code::EAGAIN`];
    /// - If `block` is `true`, blocks until an error occurs or some connection can be accepted.
    pub fn accept(&self, block: bool) -> Result<TcpStream> {
        let mut new = core::ptr::null_mut();
        let flags = if block { 0 } else { bindings::O_NONBLOCK };
        // SAFETY: The type invariant guarantees that the socket is valid, and the output argument
        // is also valid for write.
        to_result(unsafe { bindings::kernel_accept(self.sock, &mut new, flags as _) })?;
        Ok(TcpStream { sock: new })
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that the socket is valid.
        unsafe { bindings::sock_release(self.sock) };
    }
}

/// A connected TCP socket.
///
/// # Invariants
///
/// The socket pointer is always non-null and valid.
pub struct TcpStream {
    pub sock: *mut bindings::socket,
}

// SAFETY: `TcpStream` is just a wrapper for a kernel socket, which can be used from any thread.
unsafe impl Send for TcpStream {}

// SAFETY: `TcpStream` is just a wrapper for a kernel socket, which can be used from any thread.
unsafe impl Sync for TcpStream {}

impl TcpStream {
    /// Reads data from a connected socket.
    ///
    /// On success, returns the number of bytes read, which will be zero if the connection is
    /// closed.
    ///
    /// If no data is immediately available for reading, one of two behaviours will occur:
    /// - If `block` is `false`, returns [`crate::error::code::EAGAIN`];
    /// - If `block` is `true`, blocks until an error occurs, the connection is closed, or some
    ///   becomes readable.
    pub fn read(&self, buf: &mut [u8], block: bool) -> Result<usize> {
        let mut msg = bindings::msghdr::default();
        let mut vec = bindings::kvec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: The type invariant guarantees that the socket is valid, and `vec` was
        // initialised with the output buffer.
        let r = unsafe {
            bindings::kernel_recvmsg(
                self.sock,
                &mut msg,
                &mut vec,
                1,
                vec.iov_len,
                if block { 0 } else { bindings::MSG_DONTWAIT } as _,
            )
        };
        if r < 0 {
            Err(Error::from_kernel_errno(r))
        } else {
            Ok(r as _)
        }
    }

    /// Writes data to the connected socket.
    ///
    /// On success, returns the number of bytes written.
    ///
    /// If the send buffer of the socket is full, one of two behaviours will occur:
    /// - If `block` is `false`, returns [`crate::error::code::EAGAIN`];
    /// - If `block` is `true`, blocks until an error occurs or some data is written.
    pub fn write(&self, buf: &[u8], block: bool) -> Result<usize> {
        let mut msg = bindings::msghdr {
            msg_flags: if block { 0 } else { bindings::MSG_DONTWAIT },
            ..bindings::msghdr::default()
        };
        let mut vec = bindings::kvec {
            iov_base: buf.as_ptr() as *mut u8 as _,
            iov_len: buf.len(),
        };
        // SAFETY: The type invariant guarantees that the socket is valid, and `vec` was
        // initialised with the input  buffer.
        let r = unsafe { bindings::kernel_sendmsg(self.sock, &mut msg, &mut vec, 1, vec.iov_len) };
        if r < 0 {
            Err(Error::from_kernel_errno(r))
        } else {
            Ok(r as _)
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // SAFETY: The type invariant guarantees that the socket is valid.
        unsafe { bindings::sock_release(self.sock) };
    }
}

pub enum SockType {
    /// Stream socket (e.g. TCP)
    Stream = bindings::sock_type_SOCK_STREAM as isize,
    /// Connectionless socket (e.g. UDP)
    Datagram = bindings::sock_type_SOCK_DGRAM as isize,
    /// Raw socket
    Raw = bindings::sock_type_SOCK_RAW as isize,
    /// Reliably-delivered message
    Rdm = bindings::sock_type_SOCK_RDM as isize,
    /// Sequenced packet stream
    Seqpacket = bindings::sock_type_SOCK_SEQPACKET as isize,
    /// Datagram Congestion Control Protocol socket
    Dccp = bindings::sock_type_SOCK_DCCP as isize,
    /// Packet socket
    Packet = bindings::sock_type_SOCK_PACKET as isize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IpProtocol {
    /// Dummy protocol for TCP
    Ip = bindings::IPPROTO_IP as isize,
    /// Internet Control Message Protocol
    Icmp = bindings::IPPROTO_ICMP as isize,
    /// Internet Group Management Protocol
    Igmp = bindings::IPPROTO_IGMP as isize,
    /// IPIP tunnels (older KA9Q tunnels use 94)
    IpIp = bindings::IPPROTO_IPIP as isize,
    /// Transmission Control Protocol
    Tcp = bindings::IPPROTO_TCP as isize,
    /// Exterior Gateway Protocol
    Egp = bindings::IPPROTO_EGP as isize,
    /// PUP protocol
    Pup = bindings::IPPROTO_PUP as isize,
    /// User Datagram Protocol
    Udp = bindings::IPPROTO_UDP as isize,
    /// XNS Idp protocol
    Idp = bindings::IPPROTO_IDP as isize,
    /// SO Transport Protocol Class 4
    Tp = bindings::IPPROTO_TP as isize,
    /// Datagram Congestion Control Protocol
    Dccp = bindings::IPPROTO_DCCP as isize,
    /// Ipv6-in-Ipv4 tunnelling
    Ipv6 = bindings::IPPROTO_IPV6 as isize,
    /// Rsvp Protocol
    Rsvp = bindings::IPPROTO_RSVP as isize,
    /// Cisco GRE tunnels (rfc 1701,1702)
    Gre = bindings::IPPROTO_GRE as isize,
    /// Encapsulation Security Payload protocol
    Esp = bindings::IPPROTO_ESP as isize,
    /// Authentication Header protocol
    Ah = bindings::IPPROTO_AH as isize,
    /// Multicast Transport Protocol
    Mtp = bindings::IPPROTO_MTP as isize,
    /// Ip option pseudo header for BEET
    Beetph = bindings::IPPROTO_BEETPH as isize,
    /// Encapsulation Header
    Encap = bindings::IPPROTO_ENCAP as isize,
    /// Protocol Independent Multicast
    Pim = bindings::IPPROTO_PIM as isize,
    /// Compression Header Protocol
    Comp = bindings::IPPROTO_COMP as isize,
    /// Layer 2 Tunnelling Protocol
    L2Tp = bindings::IPPROTO_L2TP as isize,
    /// Stream Control Transport Protocol
    Sctp = bindings::IPPROTO_SCTP as isize,
    /// Udp-Lite (Rfc 3828)
    UdpLite = bindings::IPPROTO_UDPLITE as isize,
    /// Mpls in Ip (Rfc 4023)
    Mpls = bindings::IPPROTO_MPLS as isize,
    /// Ethernet-within-Ipv6 Encapsulation
    Ethernet = bindings::IPPROTO_ETHERNET as isize,
    /// Raw Ip packets
    Raw = bindings::IPPROTO_RAW as isize,
    /// Multipath Tcp connection
    Mptcp = bindings::IPPROTO_MPTCP as isize,
}



#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// Unspecified address family.
    Unspec = bindings::AF_UNSPEC as isize,
    /// Local to host (pipes and file-domain).
    Unix = bindings::AF_UNIX as isize,
    /// Internetwork: UDP, TCP, etc.
    Inet = bindings::AF_INET as isize,
    /// Amateur radio AX.25.
    Ax25 = bindings::AF_AX25 as isize,
    /// IPX.
    Ipx = bindings::AF_IPX as isize,
    /// Appletalk DDP.
    Appletalk = bindings::AF_APPLETALK as isize,
    /// AX.25 packet layer protocol.
    Netrom = bindings::AF_NETROM as isize,
    /// Bridge link.
    Bridge = bindings::AF_BRIDGE as isize,
    /// ATM PVCs.
    Atmpvc = bindings::AF_ATMPVC as isize,
    /// X.25 (ISO-8208).
    X25 = bindings::AF_X25 as isize,
    /// IPv6.
    Inet6 = bindings::AF_INET6 as isize,
    /// ROSE protocol.
    Rose = bindings::AF_ROSE as isize,
    /// DECnet protocol.
    Decnet = bindings::AF_DECnet as isize,
    /// 802.2LLC project.
    Netbeui = bindings::AF_NETBEUI as isize,
    /// Firewall hooks.
    Security = bindings::AF_SECURITY as isize,
    /// Key management protocol.
    Key = bindings::AF_KEY as isize,
    /// Netlink.
    Netlink = bindings::AF_NETLINK as isize,
    /// Low-level packet interface.
    Packet = bindings::AF_PACKET as isize,
    /// Acorn Econet protocol.
    Econet = bindings::AF_ECONET as isize,
    /// ATM SVCs.
    Atmsvc = bindings::AF_ATMSVC as isize,
    /// RDS sockets.
    Rds = bindings::AF_RDS as isize,
    /// IRDA sockets.
    Irda = bindings::AF_IRDA as isize,
    /// Generic PPP.
    Pppox = bindings::AF_PPPOX as isize,
    /// Legacy WAN networks protocol.
    Wanpipe = bindings::AF_WANPIPE as isize,
    /// LLC protocol.
    Llc = bindings::AF_LLC as isize,
    /// Infiniband.
    Ib = bindings::AF_IB as isize,
    /// Multiprotocol label switching.
    Mpls = bindings::AF_MPLS as isize,
    /// Controller Area Network.
    Can = bindings::AF_CAN as isize,
    /// TIPC sockets.
    Tipc = bindings::AF_TIPC as isize,
    /// Bluetooth sockets.
    Bluetooth = bindings::AF_BLUETOOTH as isize,
    /// IUCV sockets.
    Iucv = bindings::AF_IUCV as isize,
    /// RxRPC sockets.
    Rxrpc = bindings::AF_RXRPC as isize,
    /// Modular ISDN protocol.
    Isdn = bindings::AF_ISDN as isize,
    /// Nokia cellular modem interface.
    Phonet = bindings::AF_PHONET as isize,
    /// IEEE 802.15.4 sockets.
    Ieee802154 = bindings::AF_IEEE802154 as isize,
    /// CAIF sockets.
    Caif = bindings::AF_CAIF as isize,
    /// Kernel crypto API
    Alg = bindings::AF_ALG as isize,
    /// VMware VSockets.
    Vsock = bindings::AF_VSOCK as isize,
    /// KCM sockets.
    Kcm = bindings::AF_KCM as isize,
    /// Qualcomm IPC router protocol.
    Qipcrtr = bindings::AF_QIPCRTR as isize,
    /// SMC sockets.
    Smc = bindings::AF_SMC as isize,
    /// Express Data Path sockets.
    Xdp = bindings::AF_XDP as isize,
}

pub struct Socket(*mut bindings::socket);

impl Socket {
    /// Retrieve the flags associated with the socket.
    ///
    /// Unfortunately, these flags cannot be represented as a [`FlagSet`], since [`SocketFlag`]s
    /// are not represented as masks but as the index of the bit they represent.
    ///
    /// An enum could be created, containing masks instead of indexes, but this could create
    /// confusion with the C side.
    ///
    /// The methods [`Socket::has_flag`] and [`Socket::set_flags`] can be used to check and set individual flags.
    pub fn flags(&self) -> u64 {
        unsafe { (*self.0).flags }
    }

    /// Set the flags associated with the socket.
    pub fn set_flags(&self, flags: u64) {
        unsafe {
            (*self.0).flags = flags;
        }
    }


    /// Consumes the socket and returns the underlying pointer.
    ///
    /// The pointer is valid for the lifetime of the wrapper.
    ///
    /// # Safety
    /// The caller must ensure that the pointer is not used after the wrapper is dropped.
    pub unsafe fn into_inner(self) -> *mut bindings::socket {
        self.0
    }

    /// Returns the underlying pointer.
    ///
    /// The pointer is valid for the lifetime of the wrapper.
    ///
    /// # Safety
    /// The caller must ensure that the pointer is not used after the wrapper is dropped.
    pub unsafe fn as_inner(&self) -> *mut bindings::socket {
        self.0
    }
}


// Socket API implementation
impl Socket {
    /// Private utility function to create a new socket by calling a function.
    /// The function is generic over the creation function.
    ///
    /// # Arguments
    /// * `create_fn`: A function that initiates the socket given as parameter.
    ///                The function must return 0 on success and a negative error code on failure.
    fn base_new<T>(create_fn: T) -> Result<Self>
    where
        T: (FnOnce(*mut *mut bindings::socket) -> core::ffi::c_int),
    {
        let mut socket_ptr: *mut bindings::socket = core::ptr::null_mut();
        to_result(create_fn(&mut socket_ptr))?;
        Ok(Self(socket_ptr))
    }

    pub fn new(family: AddressFamily, type_: SockType, proto: IpProtocol) -> Result<Self> {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create(family as _, type_ as _, proto as _, socket_ptr)
        })
    }


    pub fn connect(&self, address: &SocketAddr, flags: i32) -> Result {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        unsafe {
            to_result(bindings::kernel_connect(
                self.0,
                address.as_ptr() as _,
                address.size() as _,
                flags,
            ))
        }
    }

    
    /// Create a new socket in a specific namespace.
    ///
    /// Wraps the `sock_create_kern` function.
    pub fn new_kern(
        ns: &Namespace,
        family: AddressFamily,
        type_: SockType,
        proto: IpProtocol,
    ) -> Result<Self> {
        // SAFETY: FFI call; the address is valid for the lifetime of the wrapper.
        Self::base_new(|socket_ptr| unsafe {
            bindings::sock_create_kern(ns.0.get(), family as _, type_ as _, proto as _, socket_ptr)
        })
    }
}
