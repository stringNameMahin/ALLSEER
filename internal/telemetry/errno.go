package telemetry

// Symbolic names for the Linux errno values a syscall can return.
//
// # Why this table exists here
//
// The header states the convention on `__s32 ret`: "syscall return; negative is
// -errno". event.Result carries both the raw number and a symbolic name, and
// the decoder is the only place in the system that sees the raw one -- every
// stage after it consumes event.Event. So if the name is not attached here it
// is never attached at all, and the audit record is left holding "-2" where the
// difference between reading a credential file and failing to read one is the
// whole finding. The credential-egress fixture turns on exactly that: a read of
// ~/.ssh/id_ed25519 that failed with ENOENT "disclosed nothing, so there is
// nothing that could subsequently leave".
//
// # Why it is written out rather than taken from the standard library
//
// syscall.Errno.Error() would answer this on Linux and answers something else
// entirely on Windows, where most of this repository is currently developed --
// and a decoder that produces different audit records depending on the host it
// runs on is not a decoder anyone can trust a golden file against.
// golang.org/x/sys carries the table, and taking a second dependency for a
// hundred and thirty string constants would not survive the dependency
// discipline in devRead section 9.2.
//
// # What it covers
//
// The asm-generic list, which is what x86-64 and arm64 both use -- the two
// targets internal/telemetry/abi is generated for. Values 1-133, with 41 and 58
// unassigned on Linux. Alpha, MIPS, PA-RISC and SPARC renumber much of the
// range above 34; none is a supported target, and a build for one would need
// this table regenerated rather than adjusted.
//
// Values outside the table yield the empty string rather than an invented name.
// ReturnCode still carries the number, so nothing is lost and nothing is made
// up. Kernel-internal codes such as ERESTARTSYS (512) live above the table
// deliberately: they never reach user space, so one appearing in a record means
// the probe reported something a syscall could not have returned, and naming it
// would disguise that.

// errnoNames is indexed by errno value. Index 0 is unused: errno 0 is success,
// and resultOf only consults this table for a negative return.
var errnoNames = [...]string{
	1:   "EPERM",
	2:   "ENOENT",
	3:   "ESRCH",
	4:   "EINTR",
	5:   "EIO",
	6:   "ENXIO",
	7:   "E2BIG",
	8:   "ENOEXEC",
	9:   "EBADF",
	10:  "ECHILD",
	11:  "EAGAIN",
	12:  "ENOMEM",
	13:  "EACCES",
	14:  "EFAULT",
	15:  "ENOTBLK",
	16:  "EBUSY",
	17:  "EEXIST",
	18:  "EXDEV",
	19:  "ENODEV",
	20:  "ENOTDIR",
	21:  "EISDIR",
	22:  "EINVAL",
	23:  "ENFILE",
	24:  "EMFILE",
	25:  "ENOTTY",
	26:  "ETXTBSY",
	27:  "EFBIG",
	28:  "ENOSPC",
	29:  "ESPIPE",
	30:  "EROFS",
	31:  "EMLINK",
	32:  "EPIPE",
	33:  "EDOM",
	34:  "ERANGE",
	35:  "EDEADLK",
	36:  "ENAMETOOLONG",
	37:  "ENOLCK",
	38:  "ENOSYS",
	39:  "ENOTEMPTY",
	40:  "ELOOP",
	42:  "ENOMSG",
	43:  "EIDRM",
	44:  "ECHRNG",
	45:  "EL2NSYNC",
	46:  "EL3HLT",
	47:  "EL3RST",
	48:  "ELNRNG",
	49:  "EUNATCH",
	50:  "ENOCSI",
	51:  "EL2HLT",
	52:  "EBADE",
	53:  "EBADR",
	54:  "EXFULL",
	55:  "ENOANO",
	56:  "EBADRQC",
	57:  "EBADSLT",
	59:  "EBFONT",
	60:  "ENOSTR",
	61:  "ENODATA",
	62:  "ETIME",
	63:  "ENOSR",
	64:  "ENONET",
	65:  "ENOPKG",
	66:  "EREMOTE",
	67:  "ENOLINK",
	68:  "EADV",
	69:  "ESRMNT",
	70:  "ECOMM",
	71:  "EPROTO",
	72:  "EMULTIHOP",
	73:  "EDOTDOT",
	74:  "EBADMSG",
	75:  "EOVERFLOW",
	76:  "ENOTUNIQ",
	77:  "EBADFD",
	78:  "EREMCHG",
	79:  "ELIBACC",
	80:  "ELIBBAD",
	81:  "ELIBSCN",
	82:  "ELIBMAX",
	83:  "ELIBEXEC",
	84:  "EILSEQ",
	85:  "ERESTART",
	86:  "ESTRPIPE",
	87:  "EUSERS",
	88:  "ENOTSOCK",
	89:  "EDESTADDRREQ",
	90:  "EMSGSIZE",
	91:  "EPROTOTYPE",
	92:  "ENOPROTOOPT",
	93:  "EPROTONOSUPPORT",
	94:  "ESOCKTNOSUPPORT",
	95:  "EOPNOTSUPP",
	96:  "EPFNOSUPPORT",
	97:  "EAFNOSUPPORT",
	98:  "EADDRINUSE",
	99:  "EADDRNOTAVAIL",
	100: "ENETDOWN",
	101: "ENETUNREACH",
	102: "ENETRESET",
	103: "ECONNABORTED",
	104: "ECONNRESET",
	105: "ENOBUFS",
	106: "EISCONN",
	107: "ENOTCONN",
	108: "ESHUTDOWN",
	109: "ETOOMANYREFS",
	110: "ETIMEDOUT",
	111: "ECONNREFUSED",
	112: "EHOSTDOWN",
	113: "EHOSTUNREACH",
	114: "EALREADY",
	115: "EINPROGRESS",
	116: "ESTALE",
	117: "EUCLEAN",
	118: "ENOTNAM",
	119: "ENAVAIL",
	120: "EISNAM",
	121: "EREMOTEIO",
	122: "EDQUOT",
	123: "ENOMEDIUM",
	124: "EMEDIUMTYPE",
	125: "ECANCELED",
	126: "ENOKEY",
	127: "EKEYEXPIRED",
	128: "EKEYREVOKED",
	129: "EKEYREJECTED",
	130: "EOWNERDEAD",
	131: "ENOTRECOVERABLE",
	132: "ERFKILL",
	133: "EHWPOISON",
}

// errnoName returns the symbolic name for a positive errno value, or the empty
// string for one this build has no name for.
//
// Table lookup rather than a switch so the cost is a bounds check and an index,
// and so the table above reads as data -- which is what it is, and what makes it
// checkable line by line against errno-base.h.
func errnoName(errno int64) string {
	if errno < 0 || errno >= int64(len(errnoNames)) {
		return ""
	}
	return errnoNames[errno]
}
