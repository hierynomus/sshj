/* Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
 * Original: http://cds.xs4all.nl:8081/ecdh/
 */
/* Generic 64-bit integer implementation of Curve25519 ECDH
 * Written by Matthijs van Duin, 200608242056
 * Public domain.
 *
 * Based on work by Daniel J Bernstein, http://cr.yp.to/ecdh.html
 */
package djb;

public class Curve25519 {

	/* key size */
	public static final int KEY_SIZE = 32;
	
	/* 0 */
	public static final byte[] ZERO = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	
	/* the prime 2^255-19 */
	public static final byte[] PRIME = {
		(byte)237, (byte)255, (byte)255, (byte)255,
		(byte)255, (byte)255, (byte)255, (byte)255,
		(byte)255, (byte)255, (byte)255, (byte)255,
		(byte)255, (byte)255, (byte)255, (byte)255,
		(byte)255, (byte)255, (byte)255, (byte)255,
		(byte)255, (byte)255, (byte)255, (byte)255,
	    (byte)255, (byte)255, (byte)255, (byte)255,
	    (byte)255, (byte)255, (byte)255, (byte)127
	};
	
	/* group order (a prime near 2^252+2^124) */
	public static final byte[] ORDER = {
		(byte)237, (byte)211, (byte)245, (byte)92,
		(byte)26,  (byte)99,  (byte)18,  (byte)88,
		(byte)214, (byte)156, (byte)247, (byte)162,
		(byte)222, (byte)249, (byte)222, (byte)20,
		(byte)0,   (byte)0,   (byte)0,   (byte)0, 
		(byte)0,   (byte)0,   (byte)0,   (byte)0,
		(byte)0,   (byte)0,   (byte)0,   (byte)0, 
		(byte)0,   (byte)0,   (byte)0,   (byte)16
	};
	
	/********* KEY AGREEMENT *********/
	
	/* Private key clamping
	 *   k [out] your private key for key agreement
	 *   k  [in]  32 random bytes
	 */
	public static final void clamp(byte[] k) {
		k[31] &= 0x7F;
		k[31] |= 0x40;
		k[ 0] &= 0xF8;
	}
	
	/* Key-pair generation
	 *   P  [out] your public key
	 *   s  [out] your private key for signing
	 *   k  [out] your private key for key agreement
	 *   k  [in]  32 random bytes
	 * s may be NULL if you don't care
	 *
	 * WARNING: if s is not NULL, this function has data-dependent timing */
	public static final void keygen(byte[] P, byte[] s, byte[] k) {
		clamp(k);
		core(P, s, k, null);
	}

	/* Key agreement
	 *   Z  [out] shared secret (needs hashing before use)
	 *   k  [in]  your private key for key agreement
	 *   P  [in]  peer's public key
	 */
	public static final void curve(byte[] Z, byte[] k, byte[] P) {
		core(Z, null, k, P);
	}
	
	/********* DIGITAL SIGNATURES *********/

	/* deterministic EC-KCDSA
	 *
	 *    s is the private key for signing
	 *    P is the corresponding public key
	 *    Z is the context data (signer public key or certificate, etc)
	 *
	 * signing:
	 *
	 *    m = hash(Z, message)
	 *    x = hash(m, s)
	 *    keygen25519(Y, NULL, x);
	 *    r = hash(Y);
	 *    h = m XOR r
	 *    sign25519(v, h, x, s);
	 *
	 *    output (v,r) as the signature
	 *
	 * verification:
	 *
	 *    m = hash(Z, message);
	 *    h = m XOR r
	 *    verify25519(Y, v, h, P)
	 *
	 *    confirm  r == hash(Y)
	 *
	 * It would seem to me that it would be simpler to have the signer directly do 
	 * h = hash(m, Y) and send that to the recipient instead of r, who can verify 
	 * the signature by checking h == hash(m, Y).  If there are any problems with 
	 * such a scheme, please let me know.
	 *
	 * Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of 
	 * perfectly good entropy, but does allow Y to be calculated in advance of (or 
	 * parallel to) hashing the message.
	 */
	
	/* Signature generation primitive, calculates (x-h)s mod q
	 *   v  [out] signature value
	 *   h  [in]  signature hash (of message, signature pub key, and context data)
	 *   x  [in]  signature private key
	 *   s  [in]  private key for signing
	 * returns true on success, false on failure (use different x or h)
	 */
	public static final boolean sign(byte[] v, byte[] h, byte[] x, byte[] s) {
		// v = (x - h) s  mod q
		int w, i;
		byte[] h1 = new byte[32], x1 = new byte[32];
		byte[] tmp1 = new byte[64];
		byte[] tmp2 = new byte[64];

		// Don't clobber the arguments, be nice!
		cpy32(h1, h);
		cpy32(x1, x);

		// Reduce modulo group order
		byte[] tmp3=new byte[32];
		divmod(tmp3, h1, 32, ORDER, 32);
		divmod(tmp3, x1, 32, ORDER, 32);

		// v = x1 - h1
		// If v is negative, add the group order to it to become positive.
		// If v was already positive we don't have to worry about overflow
		// when adding the order because v < ORDER and 2*ORDER < 2^256
		mula_small(v, x1, 0, h1, 32, -1);
		mula_small(v, v , 0, ORDER, 32, 1);

		// tmp1 = (x-h)*s mod q
		mula32(tmp1, v, s, 32, 1);
		divmod(tmp2, tmp1, 64, ORDER, 32);

		for (w = 0, i = 0; i < 32; i++)
			w |= v[i] = tmp1[i];
		return w != 0;
	}

	/* Signature verification primitive, calculates Y = vP + hG
	 *   Y  [out] signature public key
	 *   v  [in]  signature value
	 *   h  [in]  signature hash
	 *   P  [in]  public key
	 */
	public static final void verify(byte[] Y, byte[] v, byte[] h, byte[] P) {
		/* Y = v abs(P) + h G  */
		byte[] d=new byte[32];
	    long10[] 
	        p=new long10[]{new long10(),new long10()},
	    	s=new long10[]{new long10(),new long10()},
		    yx=new long10[]{new long10(),new long10(),new long10()},
		    yz=new long10[]{new long10(),new long10(),new long10()},
		    t1=new long10[]{new long10(),new long10(),new long10()},
		    t2=new long10[]{new long10(),new long10(),new long10()};
		
		int vi = 0, hi = 0, di = 0, nvh=0, i, j, k;

		/* set p[0] to G and p[1] to P  */

		set(p[0], 9);
		unpack(p[1], P);

		/* set s[0] to P+G and s[1] to P-G  */

		/* s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */
		/* s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */

		x_to_y2(t1[0], t2[0], p[1]);	/* t2[0] = Py^2  */
		sqrt(t1[0], t2[0]);	/* t1[0] = Py or -Py  */
		j = is_negative(t1[0]);		/*      ... check which  */
		t2[0]._0 += 39420360;		/* t2[0] = Py^2 + Gy^2  */
		mul(t2[1], BASE_2Y, t1[0]);/* t2[1] = 2 Py Gy or -2 Py Gy  */
		sub(t1[j], t2[0], t2[1]);	/* t1[0] = Py^2 + Gy^2 - 2 Py Gy  */
		add(t1[1-j], t2[0], t2[1]);/* t1[1] = Py^2 + Gy^2 + 2 Py Gy  */
		cpy(t2[0], p[1]);		/* t2[0] = Px  */
		t2[0]._0 -= 9;			/* t2[0] = Px - Gx  */
		sqr(t2[1], t2[0]);		/* t2[1] = (Px - Gx)^2  */
		recip(t2[0], t2[1], 0);	/* t2[0] = 1/(Px - Gx)^2  */
		mul(s[0], t1[0], t2[0]);	/* s[0] = t1[0]/(Px - Gx)^2  */
		sub(s[0], s[0], p[1]);	/* s[0] = t1[0]/(Px - Gx)^2 - Px  */
		s[0]._0 -= 9 + 486662;		/* s[0] = X(P+G)  */
		mul(s[1], t1[1], t2[0]);	/* s[1] = t1[1]/(Px - Gx)^2  */
		sub(s[1], s[1], p[1]);	/* s[1] = t1[1]/(Px - Gx)^2 - Px  */
		s[1]._0 -= 9 + 486662;		/* s[1] = X(P-G)  */
		mul_small(s[0], s[0], 1);	/* reduce s[0] */
		mul_small(s[1], s[1], 1);	/* reduce s[1] */


		/* prepare the chain  */
		for (i = 0; i < 32; i++) {
			vi = (vi >> 8) ^ (v[i] & 0xFF) ^ ((v[i] & 0xFF) << 1);
			hi = (hi >> 8) ^ (h[i] & 0xFF) ^ ((h[i] & 0xFF) << 1);
			nvh = ~(vi ^ hi);
			di = (nvh & (di & 0x80) >> 7) ^ vi;
			di ^= nvh & (di & 0x01) << 1;
			di ^= nvh & (di & 0x02) << 1;
			di ^= nvh & (di & 0x04) << 1;
			di ^= nvh & (di & 0x08) << 1;
			di ^= nvh & (di & 0x10) << 1;
			di ^= nvh & (di & 0x20) << 1;
			di ^= nvh & (di & 0x40) << 1;
			d[i] = (byte)di;
		}

		di = ((nvh & (di & 0x80) << 1) ^ vi) >> 8;

		/* initialize state */
		set(yx[0], 1);
		cpy(yx[1], p[di]);
		cpy(yx[2], s[0]);
		set(yz[0], 0);
		set(yz[1], 1);
		set(yz[2], 1);

		/* y[0] is (even)P + (even)G
		 * y[1] is (even)P + (odd)G  if current d-bit is 0
		 * y[1] is (odd)P + (even)G  if current d-bit is 1
		 * y[2] is (odd)P + (odd)G
		 */

		vi = 0;
		hi = 0;

		/* and go for it! */
		for (i = 32; i--!=0; ) {
			vi = (vi << 8) | (v[i] & 0xFF);
			hi = (hi << 8) | (h[i] & 0xFF);
			di = (di << 8) | (d[i] & 0xFF);

			for (j = 8; j--!=0; ) {
				mont_prep(t1[0], t2[0], yx[0], yz[0]);
				mont_prep(t1[1], t2[1], yx[1], yz[1]);
				mont_prep(t1[2], t2[2], yx[2], yz[2]);

				k = ((vi ^ vi >> 1) >> j & 1)
				  + ((hi ^ hi >> 1) >> j & 1);
				mont_dbl(yx[2], yz[2], t1[k], t2[k], yx[0], yz[0]);

				k = (di >> j & 2) ^ ((di >> j & 1) << 1);
				mont_add(t1[1], t2[1], t1[k], t2[k], yx[1], yz[1],
						p[di >> j & 1]);

				mont_add(t1[2], t2[2], t1[0], t2[0], yx[2], yz[2],
						s[((vi ^ hi) >> j & 2) >> 1]);
			}
		}

		k = (vi & 1) + (hi & 1);
		recip(t1[0], yz[k], 0);
		mul(t1[1], yx[k], t1[0]);

		pack(t1[1], Y);
	}
	
	/////////////////////////////////////////////////////////////////////////// 
	
	/* sahn0:
	 * Using this class instead of long[10] to avoid bounds checks. */
	private static final class long10 {
		public long10() {}
		public long10(
			long _0, long _1, long _2, long _3, long _4,
			long _5, long _6, long _7, long _8, long _9)
		{
			this._0=_0; this._1=_1; this._2=_2;
			this._3=_3; this._4=_4; this._5=_5;
			this._6=_6; this._7=_7; this._8=_8;
			this._9=_9;
		}
		public long _0,_1,_2,_3,_4,_5,_6,_7,_8,_9;
	}
	
	/********************* radix 2^8 math *********************/
	
	private static final void cpy32(byte[] d, byte[] s) {
		int i;
		for (i = 0; i < 32; i++)
			d[i] = s[i];
	}
	
	/* p[m..n+m-1] = q[m..n+m-1] + z * x */
	/* n is the size of x */
	/* n+m is the size of p and q */
	private static final int mula_small(byte[] p,byte[] q,int m,byte[] x,int n,int z) {
		int v=0;
		for (int i=0;i<n;++i) {
			v+=(q[i+m] & 0xFF)+z*(x[i] & 0xFF);
			p[i+m]=(byte)v;
			v>>=8;
		}
		return v;		
	}
	
	/* p += x * y * z  where z is a small integer
	 * x is size 32, y is size t, p is size 32+t
	 * y is allowed to overlap with p+32 if you don't care about the upper half  */
	private static final int mula32(byte[] p, byte[] x, byte[] y, int t, int z) {
		final int n = 31;
		int w = 0;
		int i = 0;
		for (; i < t; i++) {
			int zy = z * (y[i] & 0xFF);
			w += mula_small(p, p, i, x, n, zy) +
				(p[i+n] & 0xFF) + zy * (x[n] & 0xFF);
			p[i+n] = (byte)w;
			w >>= 8;
		}
		p[i+n] = (byte)(w + (p[i+n] & 0xFF));
		return w >> 8;
	}
	
	/* divide r (size n) by d (size t), returning quotient q and remainder r
	 * quotient is size n-t+1, remainder is size t
	 * requires t > 0 && d[t-1] != 0
	 * requires that r[-1] and d[-1] are valid memory locations
	 * q may overlap with r+t */
	private static final void divmod(byte[] q, byte[] r, int n, byte[] d, int t) {
		int rn = 0;
		int dt = ((d[t-1] & 0xFF) << 8);
		if (t>1) {
			dt |= (d[t-2] & 0xFF);
		}
		while (n-- >= t) {
			int z = (rn << 16) | ((r[n] & 0xFF) << 8);
			if (n>0) {
				z |= (r[n-1] & 0xFF);
			}
			z/=dt;
			rn += mula_small(r,r, n-t+1, d, t, -z);
			q[n-t+1] = (byte)((z + rn) & 0xFF); /* rn is 0 or -1 (underflow) */
			mula_small(r,r, n-t+1, d, t, -rn);
			rn = (r[n] & 0xFF);
			r[n] = 0;
		}
		r[t-1] = (byte)rn;
	}
	
	private static final int numsize(byte[] x,int n) {
		while (n--!=0 && x[n]==0)
			;
		return n+1;
	}
	
	/* Returns x if a contains the gcd, y if b.
	 * Also, the returned buffer contains the inverse of a mod b,
	 * as 32-byte signed.
	 * x and y must have 64 bytes space for temporary use.
	 * requires that a[-1] and b[-1] are valid memory locations  */
	private static final byte[] egcd32(byte[] x,byte[] y,byte[] a,byte[] b) {
		int an, bn = 32, qn, i;
		for (i = 0; i < 32; i++)
			x[i] = y[i] = 0;
		x[0] = 1;
		an = numsize(a, 32);
		if (an==0)
			return y;	/* division by zero */
		byte[] temp=new byte[32];
		while (true) {
			qn = bn - an + 1;
			divmod(temp, b, bn, a, an);
			bn = numsize(b, bn);
			if (bn==0)
				return x;
			mula32(y, x, temp, qn, -1);

			qn = an - bn + 1;
			divmod(temp, a, an, b, bn);
			an = numsize(a, an);
			if (an==0)
				return y;
			mula32(x, y, temp, qn, -1);
		}
	}
	
	/********************* radix 2^25.5 GF(2^255-19) math *********************/	
	
	private static final int P25=33554431;	/* (1 << 25) - 1 */
	private static final int P26=67108863;	/* (1 << 26) - 1 */
	
	/* Convert to internal format from little-endian byte format */
	private static final void unpack(long10 x,byte[] m) {
		x._0 = ((m[0] & 0xFF))         | ((m[1] & 0xFF))<<8 |
				(m[2] & 0xFF)<<16      | ((m[3] & 0xFF)& 3)<<24;
		x._1 = ((m[3] & 0xFF)&~ 3)>>2  | (m[4] & 0xFF)<<6 |
				(m[5] & 0xFF)<<14 | ((m[6] & 0xFF)& 7)<<22;
		x._2 = ((m[6] & 0xFF)&~ 7)>>3  | (m[7] & 0xFF)<<5 |
				(m[8] & 0xFF)<<13 | ((m[9] & 0xFF)&31)<<21;
		x._3 = ((m[9] & 0xFF)&~31)>>5  | (m[10] & 0xFF)<<3 |
				(m[11] & 0xFF)<<11 | ((m[12] & 0xFF)&63)<<19;
		x._4 = ((m[12] & 0xFF)&~63)>>6 | (m[13] & 0xFF)<<2 |
				(m[14] & 0xFF)<<10 |  (m[15] & 0xFF)    <<18;
		x._5 =  (m[16] & 0xFF)         | (m[17] & 0xFF)<<8 |
				(m[18] & 0xFF)<<16 | ((m[19] & 0xFF)& 1)<<24;
		x._6 = ((m[19] & 0xFF)&~ 1)>>1 | (m[20] & 0xFF)<<7 |
				(m[21] & 0xFF)<<15 | ((m[22] & 0xFF)& 7)<<23;
		x._7 = ((m[22] & 0xFF)&~ 7)>>3 | (m[23] & 0xFF)<<5 |
				(m[24] & 0xFF)<<13 | ((m[25] & 0xFF)&15)<<21;
		x._8 = ((m[25] & 0xFF)&~15)>>4 | (m[26] & 0xFF)<<4 |
				(m[27] & 0xFF)<<12 | ((m[28] & 0xFF)&63)<<20;
		x._9 = ((m[28] & 0xFF)&~63)>>6 | (m[29] & 0xFF)<<2 |
				(m[30] & 0xFF)<<10 |  (m[31] & 0xFF)    <<18;
	}
	
	/* Check if reduced-form input >= 2^255-19 */
	private static final boolean is_overflow(long10 x) {
		return (
			((x._0 > P26-19)) &&
			((x._1 & x._3 & x._5 & x._7 & x._9) == P25) &&
			((x._2 & x._4 & x._6 & x._8) == P26)
			) || (x._9 > P25);
	}
	
	/* Convert from internal format to little-endian byte format.  The 
	 * number must be in a reduced form which is output by the following ops:
	 *     unpack, mul, sqr
	 *     set --  if input in range 0 .. P25
	 * If you're unsure if the number is reduced, first multiply it by 1.  */
	private static final void pack(long10 x,byte[] m) {
		int ld = 0, ud = 0;
		long t;
		ld = (is_overflow(x)?1:0) - ((x._9 < 0)?1:0);
		ud = ld * -(P25+1);
		ld *= 19;
		t = ld + x._0 + (x._1 << 26);
		m[ 0] = (byte)t;
		m[ 1] = (byte)(t >> 8);
		m[ 2] = (byte)(t >> 16);
		m[ 3] = (byte)(t >> 24);
		t = (t >> 32) + (x._2 << 19);
		m[ 4] = (byte)t;
		m[ 5] = (byte)(t >> 8);
		m[ 6] = (byte)(t >> 16);
		m[ 7] = (byte)(t >> 24);
		t = (t >> 32) + (x._3 << 13);
		m[ 8] = (byte)t;
		m[ 9] = (byte)(t >> 8);
		m[10] = (byte)(t >> 16);
		m[11] = (byte)(t >> 24);
		t = (t >> 32) + (x._4 <<  6);
		m[12] = (byte)t;
		m[13] = (byte)(t >> 8);
		m[14] = (byte)(t >> 16);
		m[15] = (byte)(t >> 24);
		t = (t >> 32) + x._5 + (x._6 << 25);
		m[16] = (byte)t;
		m[17] = (byte)(t >> 8);
		m[18] = (byte)(t >> 16);
		m[19] = (byte)(t >> 24);
		t = (t >> 32) + (x._7 << 19);
		m[20] = (byte)t;
		m[21] = (byte)(t >> 8);
		m[22] = (byte)(t >> 16);
		m[23] = (byte)(t >> 24);
		t = (t >> 32) + (x._8 << 12);
		m[24] = (byte)t;
		m[25] = (byte)(t >> 8);
		m[26] = (byte)(t >> 16);
		m[27] = (byte)(t >> 24);
		t = (t >> 32) + ((x._9 + ud) << 6);
		m[28] = (byte)t;
		m[29] = (byte)(t >> 8);
		m[30] = (byte)(t >> 16);
		m[31] = (byte)(t >> 24);
	}

	/* Copy a number */
	private static final void cpy(long10 out, long10 in) {
		out._0=in._0;	out._1=in._1;
		out._2=in._2;	out._3=in._3;
		out._4=in._4;	out._5=in._5;
		out._6=in._6;	out._7=in._7;
		out._8=in._8;	out._9=in._9;		
	}

	/* Set a number to value, which must be in range -185861411 .. 185861411 */
	private static final void set(long10 out, int in) {
		out._0=in;	out._1=0;
		out._2=0;	out._3=0;
		out._4=0;	out._5=0;
		out._6=0;	out._7=0;
		out._8=0;	out._9=0;		
	}
	
	/* Add/subtract two numbers.  The inputs must be in reduced form, and the 
	 * output isn't, so to do another addition or subtraction on the output, 
	 * first multiply it by one to reduce it. */
	private static final void add(long10 xy, long10 x, long10 y) {
		xy._0 = x._0 + y._0;	xy._1 = x._1 + y._1;
		xy._2 = x._2 + y._2;	xy._3 = x._3 + y._3;
		xy._4 = x._4 + y._4;	xy._5 = x._5 + y._5;
		xy._6 = x._6 + y._6;	xy._7 = x._7 + y._7;
		xy._8 = x._8 + y._8;	xy._9 = x._9 + y._9;
	}
	private static final void sub(long10 xy, long10 x, long10 y) {
		xy._0 = x._0 - y._0;	xy._1 = x._1 - y._1;
		xy._2 = x._2 - y._2;	xy._3 = x._3 - y._3;
		xy._4 = x._4 - y._4;	xy._5 = x._5 - y._5;
		xy._6 = x._6 - y._6;	xy._7 = x._7 - y._7;
		xy._8 = x._8 - y._8;	xy._9 = x._9 - y._9;
	}
	
	/* Multiply a number by a small integer in range -185861411 .. 185861411.
	 * The output is in reduced form, the input x need not be.  x and xy may point
	 * to the same buffer. */
	private static final long10 mul_small(long10 xy, long10 x, long y) {
		long t;
		t = (x._8*y);
		xy._8 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x._9*y);
		xy._9 = (t & ((1 << 25) - 1));
		t = 19 * (t >> 25) + (x._0*y);
		xy._0 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x._1*y);
		xy._1 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x._2*y);
		xy._2 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x._3*y);
		xy._3 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x._4*y);
		xy._4 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x._5*y);
		xy._5 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x._6*y);
		xy._6 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x._7*y);
		xy._7 = (t & ((1 << 25) - 1));
		t = (t >> 25) + xy._8;
		xy._8 = (t & ((1 << 26) - 1));
		xy._9 += (t >> 26);
		return xy;
	}

	/* Multiply two numbers.  The output is in reduced form, the inputs need not 
	 * be. */
	private static final long10 mul(long10 xy, long10 x, long10 y) {
		/* sahn0:
		 * Using local variables to avoid class access.
		 * This seem to improve performance a bit...
		 */
		long
			x_0=x._0,x_1=x._1,x_2=x._2,x_3=x._3,x_4=x._4,
			x_5=x._5,x_6=x._6,x_7=x._7,x_8=x._8,x_9=x._9;
		long
			y_0=y._0,y_1=y._1,y_2=y._2,y_3=y._3,y_4=y._4,
			y_5=y._5,y_6=y._6,y_7=y._7,y_8=y._8,y_9=y._9;
		long t;
		t = (x_0*y_8) + (x_2*y_6) + (x_4*y_4) + (x_6*y_2) +
			(x_8*y_0) + 2 * ((x_1*y_7) + (x_3*y_5) +
					(x_5*y_3) + (x_7*y_1)) + 38 *
			(x_9*y_9);
		xy._8 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x_0*y_9) + (x_1*y_8) + (x_2*y_7) +
			(x_3*y_6) + (x_4*y_5) + (x_5*y_4) +
			(x_6*y_3) + (x_7*y_2) + (x_8*y_1) +
			(x_9*y_0);
		xy._9 = (t & ((1 << 25) - 1));
		t = (x_0*y_0) + 19 * ((t >> 25) + (x_2*y_8) + (x_4*y_6)
				+ (x_6*y_4) + (x_8*y_2)) + 38 *
			((x_1*y_9) + (x_3*y_7) + (x_5*y_5) +
			 (x_7*y_3) + (x_9*y_1));
		xy._0 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x_0*y_1) + (x_1*y_0) + 19 * ((x_2*y_9)
				+ (x_3*y_8) + (x_4*y_7) + (x_5*y_6) +
				(x_6*y_5) + (x_7*y_4) + (x_8*y_3) +
				(x_9*y_2));
		xy._1 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x_0*y_2) + (x_2*y_0) + 19 * ((x_4*y_8)
				+ (x_6*y_6) + (x_8*y_4)) + 2 * (x_1*y_1)
				+ 38 * ((x_3*y_9) + (x_5*y_7) +
						(x_7*y_5) + (x_9*y_3));
		xy._2 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x_0*y_3) + (x_1*y_2) + (x_2*y_1) +
			(x_3*y_0) + 19 * ((x_4*y_9) + (x_5*y_8) +
					(x_6*y_7) + (x_7*y_6) +
					(x_8*y_5) + (x_9*y_4));
		xy._3 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x_0*y_4) + (x_2*y_2) + (x_4*y_0) + 19 *
			((x_6*y_8) + (x_8*y_6)) + 2 * ((x_1*y_3) +
								 (x_3*y_1)) + 38 *
			((x_5*y_9) + (x_7*y_7) + (x_9*y_5));
		xy._4 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x_0*y_5) + (x_1*y_4) + (x_2*y_3) +
			(x_3*y_2) + (x_4*y_1) + (x_5*y_0) + 19 *
			((x_6*y_9) + (x_7*y_8) + (x_8*y_7) +
			 (x_9*y_6));
		xy._5 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x_0*y_6) + (x_2*y_4) + (x_4*y_2) +
			(x_6*y_0) + 19 * (x_8*y_8) + 2 * ((x_1*y_5) +
					(x_3*y_3) + (x_5*y_1)) + 38 *
			((x_7*y_9) + (x_9*y_7));
		xy._6 = (t & ((1 << 26) - 1));
		t = (t >> 26) + (x_0*y_7) + (x_1*y_6) + (x_2*y_5) +
			(x_3*y_4) + (x_4*y_3) + (x_5*y_2) +
			(x_6*y_1) + (x_7*y_0) + 19 * ((x_8*y_9) +
					(x_9*y_8));
		xy._7 = (t & ((1 << 25) - 1));
		t = (t >> 25) + xy._8;
		xy._8 = (t & ((1 << 26) - 1));
		xy._9 += (t >> 26);
		return xy;
	}

	/* Square a number.  Optimization of  mul25519(x2, x, x)  */
	private static final long10 sqr(long10 x2, long10 x) {
		long
			x_0=x._0,x_1=x._1,x_2=x._2,x_3=x._3,x_4=x._4,
			x_5=x._5,x_6=x._6,x_7=x._7,x_8=x._8,x_9=x._9;
		long t;
		t = (x_4*x_4) + 2 * ((x_0*x_8) + (x_2*x_6)) + 38 *
			(x_9*x_9) + 4 * ((x_1*x_7) + (x_3*x_5));
		x2._8 = (t & ((1 << 26) - 1));
		t = (t >> 26) + 2 * ((x_0*x_9) + (x_1*x_8) + (x_2*x_7) +
				(x_3*x_6) + (x_4*x_5));
		x2._9 = (t & ((1 << 25) - 1));
		t = 19 * (t >> 25) + (x_0*x_0) + 38 * ((x_2*x_8) +
				(x_4*x_6) + (x_5*x_5)) + 76 * ((x_1*x_9)
				+ (x_3*x_7));
		x2._0 = (t & ((1 << 26) - 1));
		t = (t >> 26) + 2 * (x_0*x_1) + 38 * ((x_2*x_9) +
				(x_3*x_8) + (x_4*x_7) + (x_5*x_6));
		x2._1 = (t & ((1 << 25) - 1));
		t = (t >> 25) + 19 * (x_6*x_6) + 2 * ((x_0*x_2) +
				(x_1*x_1)) + 38 * (x_4*x_8) + 76 *
				((x_3*x_9) + (x_5*x_7));
		x2._2 = (t & ((1 << 26) - 1));
		t = (t >> 26) + 2 * ((x_0*x_3) + (x_1*x_2)) + 38 *
			((x_4*x_9) + (x_5*x_8) + (x_6*x_7));
		x2._3 = (t & ((1 << 25) - 1));
		t = (t >> 25) + (x_2*x_2) + 2 * (x_0*x_4) + 38 *
			((x_6*x_8) + (x_7*x_7)) + 4 * (x_1*x_3) + 76 *
			(x_5*x_9);
		x2._4 = (t & ((1 << 26) - 1));
		t = (t >> 26) + 2 * ((x_0*x_5) + (x_1*x_4) + (x_2*x_3))
			+ 38 * ((x_6*x_9) + (x_7*x_8));
		x2._5 = (t & ((1 << 25) - 1));
		t = (t >> 25) + 19 * (x_8*x_8) + 2 * ((x_0*x_6) +
				(x_2*x_4) + (x_3*x_3)) + 4 * (x_1*x_5) +
				76 * (x_7*x_9);
		x2._6 = (t & ((1 << 26) - 1));
		t = (t >> 26) + 2 * ((x_0*x_7) + (x_1*x_6) + (x_2*x_5) +
				(x_3*x_4)) + 38 * (x_8*x_9);
		x2._7 = (t & ((1 << 25) - 1));
		t = (t >> 25) + x2._8;
		x2._8 = (t & ((1 << 26) - 1));
		x2._9 += (t >> 26);
		return x2;
	}
	
	/* Calculates a reciprocal.  The output is in reduced form, the inputs need not 
	 * be.  Simply calculates  y = x^(p-2)  so it's not too fast. */
	/* When sqrtassist is true, it instead calculates y = x^((p-5)/8) */
	private static final void recip(long10 y, long10 x, int sqrtassist) {
		long10
		    t0=new long10(),
			t1=new long10(),
			t2=new long10(),
			t3=new long10(),
			t4=new long10();
		int i;
		/* the chain for x^(2^255-21) is straight from djb's implementation */
		sqr(t1, x);	/*  2 == 2 * 1	*/
		sqr(t2, t1);	/*  4 == 2 * 2	*/
		sqr(t0, t2);	/*  8 == 2 * 4	*/
		mul(t2, t0, x);	/*  9 == 8 + 1	*/
		mul(t0, t2, t1);	/* 11 == 9 + 2	*/
		sqr(t1, t0);	/* 22 == 2 * 11	*/
		mul(t3, t1, t2);	/* 31 == 22 + 9
					== 2^5   - 2^0	*/
		sqr(t1, t3);	/* 2^6   - 2^1	*/
		sqr(t2, t1);	/* 2^7   - 2^2	*/
		sqr(t1, t2);	/* 2^8   - 2^3	*/
		sqr(t2, t1);	/* 2^9   - 2^4	*/
		sqr(t1, t2);	/* 2^10  - 2^5	*/
		mul(t2, t1, t3);	/* 2^10  - 2^0	*/
		sqr(t1, t2);	/* 2^11  - 2^1	*/
		sqr(t3, t1);	/* 2^12  - 2^2	*/
		for (i = 1; i < 5; i++) {
			sqr(t1, t3);
			sqr(t3, t1);
		} /* t3 */		/* 2^20  - 2^10	*/
		mul(t1, t3, t2);	/* 2^20  - 2^0	*/
		sqr(t3, t1);	/* 2^21  - 2^1	*/
		sqr(t4, t3);	/* 2^22  - 2^2	*/
		for (i = 1; i < 10; i++) {
			sqr(t3, t4);
			sqr(t4, t3);
		} /* t4 */		/* 2^40  - 2^20	*/
		mul(t3, t4, t1);	/* 2^40  - 2^0	*/
		for (i = 0; i < 5; i++) {
			sqr(t1, t3);
			sqr(t3, t1);
		} /* t3 */		/* 2^50  - 2^10	*/
		mul(t1, t3, t2);	/* 2^50  - 2^0	*/
		sqr(t2, t1);	/* 2^51  - 2^1	*/
		sqr(t3, t2);	/* 2^52  - 2^2	*/
		for (i = 1; i < 25; i++) {
			sqr(t2, t3);
			sqr(t3, t2);
		} /* t3 */		/* 2^100 - 2^50 */
		mul(t2, t3, t1);	/* 2^100 - 2^0	*/
		sqr(t3, t2);	/* 2^101 - 2^1	*/
		sqr(t4, t3);	/* 2^102 - 2^2	*/
		for (i = 1; i < 50; i++) {
			sqr(t3, t4);
			sqr(t4, t3);
		} /* t4 */		/* 2^200 - 2^100 */
		mul(t3, t4, t2);	/* 2^200 - 2^0	*/
		for (i = 0; i < 25; i++) {
			sqr(t4, t3);
			sqr(t3, t4);
		} /* t3 */		/* 2^250 - 2^50	*/
		mul(t2, t3, t1);	/* 2^250 - 2^0	*/
		sqr(t1, t2);	/* 2^251 - 2^1	*/
		sqr(t2, t1);	/* 2^252 - 2^2	*/
		if (sqrtassist!=0) {
			mul(y, x, t2);	/* 2^252 - 3 */
		} else {
			sqr(t1, t2);	/* 2^253 - 2^3	*/
			sqr(t2, t1);	/* 2^254 - 2^4	*/
			sqr(t1, t2);	/* 2^255 - 2^5	*/
			mul(y, t1, t0);	/* 2^255 - 21	*/
		}
	}
	
	/* checks if x is "negative", requires reduced input */
	private static final int is_negative(long10 x) {
		return (int)(((is_overflow(x) || (x._9 < 0))?1:0) ^ (x._0 & 1));
	}
	
	/* a square root */
	private static final void sqrt(long10 x, long10 u) {
		long10 v=new long10(), t1=new long10(), t2=new long10();
		add(t1, u, u);	/* t1 = 2u		*/
		recip(v, t1, 1);	/* v = (2u)^((p-5)/8)	*/
		sqr(x, v);		/* x = v^2		*/
		mul(t2, t1, x);	/* t2 = 2uv^2		*/
		t2._0--;		/* t2 = 2uv^2-1		*/
		mul(t1, v, t2);	/* t1 = v(2uv^2-1)	*/
		mul(x, u, t1);	/* x = uv(2uv^2-1)	*/
	}
	
	/********************* Elliptic curve *********************/
	
	/* y^2 = x^3 + 486662 x^2 + x  over GF(2^255-19) */
	
	/* t1 = ax + az
	 * t2 = ax - az  */
	private static final void mont_prep(long10 t1, long10 t2, long10 ax, long10 az) {
		add(t1, ax, az);
		sub(t2, ax, az);
	}
	
	/* A = P + Q   where
	 *  X(A) = ax/az
	 *  X(P) = (t1+t2)/(t1-t2)
	 *  X(Q) = (t3+t4)/(t3-t4)
	 *  X(P-Q) = dx
	 * clobbers t1 and t2, preserves t3 and t4  */
	private static final void mont_add(long10 t1, long10 t2, long10 t3, long10 t4,long10 ax, long10 az, long10 dx) {
		mul(ax, t2, t3);
		mul(az, t1, t4);
		add(t1, ax, az);
		sub(t2, ax, az);
		sqr(ax, t1);
		sqr(t1, t2);
		mul(az, t1, dx);
	}
	
	/* B = 2 * Q   where
	 *  X(B) = bx/bz
	 *  X(Q) = (t3+t4)/(t3-t4)
	 * clobbers t1 and t2, preserves t3 and t4  */
	private static final void mont_dbl(long10 t1, long10 t2, long10 t3, long10 t4,long10 bx, long10 bz) {
		sqr(t1, t3);
		sqr(t2, t4);
		mul(bx, t1, t2);
		sub(t2, t1, t2);
		mul_small(bz, t2, 121665);
		add(t1, t1, bz);
		mul(bz, t1, t2);
	}
	
	/* Y^2 = X^3 + 486662 X^2 + X
	 * t is a temporary  */
	private static final void x_to_y2(long10 t, long10 y2, long10 x) {
		sqr(t, x);
		mul_small(y2, x, 486662);
		add(t, t, y2);
		t._0++;
		mul(y2, t, x);
	}
	
	/* P = kG   and  s = sign(P)/k  */
	private static final void core(byte[] Px, byte[] s, byte[] k, byte[] Gx) {
		long10 
		    dx=new long10(),
		    t1=new long10(),
		    t2=new long10(),
		    t3=new long10(),
		    t4=new long10();
	    long10[] 
	        x=new long10[]{new long10(),new long10()},
	    	z=new long10[]{new long10(),new long10()};
		int i, j;

		/* unpack the base */
		if (Gx!=null)
			unpack(dx, Gx);
		else
			set(dx, 9);

		/* 0G = point-at-infinity */
		set(x[0], 1);
		set(z[0], 0);

		/* 1G = G */
		cpy(x[1], dx);
		set(z[1], 1);

		for (i = 32; i--!=0; ) {
			if (i==0) {
				i=0;
			}
			for (j = 8; j--!=0; ) {
				/* swap arguments depending on bit */
				int bit1 = (k[i] & 0xFF) >> j & 1;
				int bit0 = ~(k[i] & 0xFF) >> j & 1;
				long10 ax = x[bit0];
				long10 az = z[bit0];
				long10 bx = x[bit1];
				long10 bz = z[bit1];

				/* a' = a + b	*/
				/* b' = 2 b	*/
				mont_prep(t1, t2, ax, az);
				mont_prep(t3, t4, bx, bz);
				mont_add(t1, t2, t3, t4, ax, az, dx);
				mont_dbl(t1, t2, t3, t4, bx, bz);
			}
		}

		recip(t1, z[0], 0);
		mul(dx, x[0], t1);
		pack(dx, Px);

		/* calculate s such that s abs(P) = G  .. assumes G is std base point */
		if (s!=null) {
			x_to_y2(t2, t1, dx);	/* t1 = Py^2  */
			recip(t3, z[1], 0);	/* where Q=P+G ... */
			mul(t2, x[1], t3);	/* t2 = Qx  */
			add(t2, t2, dx);	/* t2 = Qx + Px  */
			t2._0 += 9 + 486662;	/* t2 = Qx + Px + Gx + 486662  */
			dx._0 -= 9;		/* dx = Px - Gx  */
			sqr(t3, dx);	/* t3 = (Px - Gx)^2  */
			mul(dx, t2, t3);	/* dx = t2 (Px - Gx)^2  */
			sub(dx, dx, t1);	/* dx = t2 (Px - Gx)^2 - Py^2  */
			dx._0 -= 39420360;	/* dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  */
			mul(t1, dx, BASE_R2Y);	/* t1 = -Py  */
			if (is_negative(t1)!=0)	/* sign is 1, so just copy  */
				cpy32(s, k);
			else			/* sign is -1, so negate  */
				mula_small(s, ORDER_TIMES_8, 0, k, 32, -1);

			/* reduce s mod q
			 * (is this needed?  do it just in case, it's fast anyway) */
			//divmod((dstptr) t1, s, 32, order25519, 32);

			/* take reciprocal of s mod q */
			byte[] temp1=new byte[32];
			byte[] temp2=new byte[64];
			byte[] temp3=new byte[64];
			cpy32(temp1, ORDER);
			cpy32(s, egcd32(temp2, temp3, s, temp1));
			if ((s[31] & 0x80)!=0)
				mula_small(s, s, 0, ORDER, 32, 1);
		}
	}

	/* smallest multiple of the order that's >= 2^255 */
	private static final byte[] ORDER_TIMES_8 = {
		(byte)104, (byte)159, (byte)174, (byte)231,
		(byte)210, (byte)24,  (byte)147, (byte)192,
		(byte)178, (byte)230, (byte)188, (byte)23,
		(byte)245, (byte)206, (byte)247, (byte)166,
		(byte)0,   (byte)0,   (byte)0,   (byte)0,  
		(byte)0,   (byte)0,   (byte)0,   (byte)0,
		(byte)0,   (byte)0,   (byte)0,   (byte)0,  
		(byte)0,   (byte)0,   (byte)0,   (byte)128
	};
	
	/* constants 2Gy and 1/(2Gy) */
	private static final long10 BASE_2Y = new long10(
		39999547, 18689728, 59995525, 1648697, 57546132,
		24010086, 19059592, 5425144, 63499247, 16420658
	);
	private static final long10 BASE_R2Y = new long10(
		5744, 8160848, 4790893, 13779497, 35730846,
		12541209, 49101323, 30047407, 40071253, 6226132
	);
}
