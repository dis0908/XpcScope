import ObjC from "frida-objc-bridge";
import { bt } from "./utils.js";

ObjC.classes.NSBundle.bundleWithPath_(
  "/System/Library/Frameworks/Foundation.framework",
).load();

const { NSXPCListener, NSXPCConnection } = ObjC.classes;

function getConnInfo(obj: ObjC.Object): { name: string; peer: number } {
  let name = "";
  let peer = 0;
  try {
    const sn = obj.serviceName();
    if (sn) name = sn.toString();
  } catch {}
  try {
    peer = obj.processIdentifier();
  } catch {}
  return { name, peer };
}

function describeCall(
  className: string,
  handle: NativePointer,
  sel: string,
  argValues: string[],
): string {
  const parts = sel.split(":");
  const nparams = sel.includes(":") ? parts.length - 1 : 0;

  let desc = `<${className} ${handle}>`;
  if (nparams === 0) return `${desc} ${sel}`;
  for (let i = 0; i < nparams; i++) {
    desc += " ";
    desc += `${parts[i]}:${argValues[i] ?? ""}`;
  }
  return desc;
}

function readArgsFromInvocation(
  invocation: ObjC.Object,
  signature: ObjC.Object,
): string[] {
  const nargs = signature.numberOfArguments();
  const result: string[] = [];
  const buf = Memory.alloc(16);
  for (let i = 2; i < nargs; i++) {
    try {
      const t = signature.getArgumentTypeAtIndex_(i) + "";
      if (t.startsWith("@?")) {
        result.push("<block>");
      } else if (t.startsWith("@")) {
        invocation.getArgument_atIndex_(buf, i);
        const ptr = buf.readPointer();
        result.push(ptr.isNull() ? "nil" : new ObjC.Object(ptr).toString());
      } else {
        result.push(`<${t}>`);
      }
    } catch {
      result.push("<error>");
    }
  }
  return result;
}

function readObjArgsFromArray(
  argsPtr: NativePointer,
  count: number,
): string[] {
  const result: string[] = [];
  for (let i = 0; i < count; i++) {
    try {
      const arg = argsPtr.add(i * Process.pointerSize).readPointer();
      result.push(arg.isNull() ? "nil" : new ObjC.Object(arg).toString());
    } catch {
      result.push("<error>");
    }
  }
  return result;
}

function readArgsFromArray(
  argsPtr: NativePointer,
  count: number,
  signature: ObjC.Object,
): string[] {
  const result: string[] = [];
  for (let i = 0; i < count; i++) {
    try {
      const arg = argsPtr.add(i * Process.pointerSize).readPointer();
      const t = signature.getArgumentTypeAtIndex_(i + 2) + "";
      if (t.startsWith("@") && !arg.isNull()) {
        result.push(new ObjC.Object(arg).toString());
      } else if (arg.isNull()) {
        result.push("nil");
      } else {
        result.push(arg.toString());
      }
    } catch {
      result.push("<error>");
    }
  }
  return result;
}

export function listeners() {
  return ObjC.chooseSync(NSXPCListener).map((listener) => ({
    delegate: listener.delegate()?.$className,
    serviceName: listener.serviceName()?.toString(),
  }));
}

export function start() {
  hookIncoming();
  hookOutgoing();
}

// ─── Incoming NSXPC messages ──────────────────────────────────────────

function hookIncoming() {
  // Hook the decoder's output to capture decoded selector, args, and
  // connection — all from out-parameters of a single ObjC method call.
  // This runs inside _decodeAndInvokeMessageWithEvent:reply:flags:,
  // BEFORE dispatch to the exported object.
  const NSXPCDecoder = ObjC.classes.NSXPCDecoder;
  if (!NSXPCDecoder) return;

  const decode =
    NSXPCDecoder[
      "- _decodeMessageFromXPCObject:allowingSimpleMessageSend:outInvocation:outArguments:outArgumentsMaxCount:outMethodSignature:outSelector:"
    ];
  if (!decode) return;

  // args layout (ARM64):
  //  [0] self (NSXPCDecoder)  [1] _cmd
  //  [2] event                [3] allowSimpleSend
  //  [4] outInvocation**      [5] outArguments*
  //  [6] outMaxCount          [7] outMethodSignature**
  //  [8] outSelector**  (first stack arg)
  Interceptor.attach(decode.implementation, {
    onEnter(args) {
      this.decoder = args[0];
      this.outInvocationPtr = args[4];
      this.outArgsPtr = args[5];
      this.outMaxCount = args[6].toUInt32();
      this.outSignaturePtr = args[7];
      this.outSelectorPtr = args[8];
    },
    onLeave(retval) {
      if (!retval.toInt32()) return;

      try {
        const selPtr = this.outSelectorPtr.readPointer();
        if (selPtr.isNull()) return;
        const sel = ObjC.selectorAsString(selPtr);

        const sigPtr = this.outSignaturePtr.readPointer();
        if (sigPtr.isNull()) return;
        const signature = new ObjC.Object(sigPtr);

        let argValues: string[];
        const invPtr = this.outInvocationPtr.readPointer();
        if (!invPtr.isNull()) {
          argValues = readArgsFromInvocation(
            new ObjC.Object(invPtr),
            signature,
          );
        } else {
          const nargs = Math.min(
            signature.numberOfArguments() - 2,
            this.outMaxCount,
          );
          argValues = readObjArgsFromArray(this.outArgsPtr, nargs);
        }

        const decoder = new ObjC.Object(this.decoder);
        const conn = decoder.connection();
        const { name, peer } = conn ? getConnInfo(conn) : { name: "", peer: 0 };

        let targetClass = "?";
        try {
          const obj = conn?.exportedObject();
          if (obj) targetClass = obj.$className;
        } catch {}

        send({
          event: "received",
          name,
          peer,
          dir: "<",
          message: {
            type: "nsxpc",
            sel,
            args: argValues,
            description: describeCall(targetClass, ptr(0), sel, argValues),
          },
        });
      } catch {}
    },
  });
}

// ─── Outgoing NSXPC messages ──────────────────────────────────────────

function hookOutgoing() {
  // All outgoing paths (SimpleMessageSend0-4, forwardInvocation:,
  // _forwardStackInvocation:) converge into this single ObjC method.
  const sendInvocation =
    NSXPCConnection[
      "- _sendInvocation:orArguments:count:methodSignature:selector:withProxy:"
    ];

  if (sendInvocation) {
    // args: (self, _cmd, invocation, argsPtr, count, signature, selector, proxy)
    Interceptor.attach(sendInvocation.implementation, {
      onEnter(args) {
        try {
          const conn = new ObjC.Object(args[0]);
          const signature = new ObjC.Object(args[5]);
          const sel = ObjC.selectorAsString(args[6]);

          let argValues: string[];
          if (!args[2].isNull()) {
            argValues = readArgsFromInvocation(
              new ObjC.Object(args[2]),
              signature,
            );
          } else if (!args[3].isNull()) {
            argValues = readArgsFromArray(
              args[3],
              args[4].toUInt32(),
              signature,
            );
          } else {
            argValues = [];
          }

          const { name, peer } = getConnInfo(conn);
          const proxyPtr = args[7];
          const proxyClass = proxyPtr.isNull()
            ? "?"
            : new ObjC.Object(proxyPtr).$className;

          send({
            event: "sent",
            name,
            peer,
            dir: ">",
            message: {
              type: "nsxpc",
              sel,
              args: argValues,
              description: describeCall(proxyClass, proxyPtr, sel, argValues),
            },
            backtrace: bt(this.context),
          });
        } catch {}
      },
    });
    return;
  }

  // Fallback: hook individual _sendSelector:withProxy:argN: ObjC methods.
  // These only carry object-typed arguments (0-4 args).
  const variants: [string, number][] = [
    ["- _sendSelector:withProxy:", 0],
    ["- _sendSelector:withProxy:arg1:", 1],
    ["- _sendSelector:withProxy:arg1:arg2:", 2],
    ["- _sendSelector:withProxy:arg1:arg2:arg3:", 3],
    ["- _sendSelector:withProxy:arg1:arg2:arg3:arg4:", 4],
  ];

  for (const [methodSel, argc] of variants) {
    const method = NSXPCConnection[methodSel];
    if (!method) continue;

    // args: (self, _cmd, selector, proxy, arg1?, arg2?, ...)
    const argCount = argc; // capture for closure
    Interceptor.attach(method.implementation, {
      onEnter(args) {
        try {
          const conn = new ObjC.Object(args[0]);
          const sel = ObjC.selectorAsString(args[2]);
          const proxy = new ObjC.Object(args[3]);
          const { name, peer } = getConnInfo(conn);

          const argValues: string[] = [];
          for (let i = 0; i < argCount; i++) {
            try {
              const a = args[4 + i];
              argValues.push(
                a.isNull() ? "nil" : new ObjC.Object(a).toString(),
              );
            } catch {
              argValues.push("<error>");
            }
          }

          send({
            event: "sent",
            name,
            peer,
            dir: ">",
            message: {
              type: "nsxpc",
              sel,
              args: argValues,
              description: describeCall(
                proxy.$className,
                args[3],
                sel,
                argValues,
              ),
            },
            backtrace: bt(this.context),
          });
        } catch {}
      },
    });
  }

  // forwardInvocation: handles messages with >4 args or non-object args.
  const DistantObject = ObjC.classes._NSXPCDistantObject;
  if (!DistantObject) return;

  const fwd = DistantObject["- forwardInvocation:"];
  if (!fwd) return;

  Interceptor.attach(fwd.implementation, {
    onEnter(args) {
      try {
        const proxy = new ObjC.Object(args[0]);
        const invocation = new ObjC.Object(args[2]);
        const conn = proxy['_connection']();
        if (!conn) return;

        const sel = ObjC.selectorAsString(invocation.selector());
        const signature = invocation.methodSignature();
        const argValues = readArgsFromInvocation(invocation, signature);
        const { name, peer } = getConnInfo(conn);

        send({
          event: "sent",
          name,
          peer,
          dir: ">",
          message: {
            type: "nsxpc",
            sel,
            args: argValues,
            description: describeCall(
              proxy.$className,
              args[0],
              sel,
              argValues,
            ),
          },
          backtrace: bt(this.context),
        });
      } catch {}
    },
  });
}
