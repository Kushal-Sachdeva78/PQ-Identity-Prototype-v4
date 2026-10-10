pragma circom 2.1.0;

// REHEARSAL ONLY. Throwaway circuit for the ceremony rehearsal (ceremony/rehearse.mjs).
// It is not part of PQ-Identity and its key protects nothing.
// Statement: I know x (< 2^32) and salt with y = x^3 + x + 5 and tag = x * salt + 7.

template Bits(n) {
    signal input in;
    signal output out[n];
    var acc = 0;
    var e = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        acc += out[i] * e;
        e = e + e;
    }
    acc === in;
}

template Tiny() {
    signal input x;
    signal input salt;
    signal input y;
    signal input tag;

    signal x2 <== x * x;
    signal x3 <== x2 * x;
    y === x3 + x + 5;

    signal xs <== x * salt;
    tag === xs + 7;

    component range = Bits(32);
    range.in <== x;
}

component main {public [y, tag]} = Tiny();
