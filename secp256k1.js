(function(global){
  const P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
  const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  const Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
  function mod(a, m){const res=a%m;return res>=0n?res:res+m;}
  function invMod(a, m){
    if(a===0n||m<=0n) throw new Error('div by 0');
    let [lm, hm] = [1n,0n];
    let [low, high] = [mod(a,m), m];
    while(low>1n){
      let r = high/low;
      [lm, hm] = [hm - lm*r, lm];
      [low, high] = [high - low*r, low];
    }
    return mod(lm, m);
  }
  class Point{
    constructor(x,y){this.x=x;this.y=y;}
    static get ZERO(){return new Point(null,null);}
    static get BASE(){return new Point(Gx,Gy);}
    isInfinity(){return this.x===null||this.y===null;}
  }
  function pointAdd(a,b){
    if(a.isInfinity()) return b;
    if(b.isInfinity()) return a;
    if(a.x===b.x){
      if(a.y!==b.y) return Point.ZERO;
      const m = mod((3n*a.x*a.x)*invMod(2n*a.y,P), P);
      const x = mod(m*m - 2n*a.x, P);
      const y = mod(m*(a.x - x) - a.y, P);
      return new Point(x,y);
    }
    const m = mod((b.y - a.y)*invMod(b.x - a.x, P), P);
    const x = mod(m*m - a.x - b.x, P);
    const y = mod(m*(a.x - x) - a.y, P);
    return new Point(x,y);
  }
  function scalarMult(p,n){
    let r = Point.ZERO;
    let addend = p;
    while(n>0n){
      if(n&1n) r = pointAdd(r, addend);
      addend = pointAdd(addend, addend);
      n >>= 1n;
    }
    return r;
  }
  function getPublicKey(privHex){
    const d = BigInt('0x'+privHex);
    const P = scalarMult(Point.BASE, d);
    const prefix = (P.y & 1n) ? '03' : '02';
    return prefix + P.x.toString(16).padStart(64,'0');
  }
  function sha256hex(hex){
    const word = CryptoJS.enc.Hex.parse(hex);
    return CryptoJS.SHA256(word).toString();
  }
  function sign(msgHex, privHex){
    let d = BigInt('0x'+privHex);
    let k = BigInt('0x'+sha256hex(privHex + msgHex));
    k = mod(k, N-1n) + 1n;
    const R = scalarMult(Point.BASE, k);
    const r = mod(R.x, N);
    const s = mod(invMod(k,N)*(BigInt('0x'+msgHex) + r*d), N);
    return { r: r.toString(16).padStart(64,'0'), s: s.toString(16).padStart(64,'0') };
  }
  global.secp256k1 = { getPublicKey, sign };
})(typeof window !== 'undefined'?window:global);
