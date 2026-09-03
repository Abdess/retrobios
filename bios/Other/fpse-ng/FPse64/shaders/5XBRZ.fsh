precision highp float;
precision highp int;
uniform sampler2D uTex;
uniform highp float resX;
uniform highp float resY;
varying vec4 v_texture_coordinate;
varying vec4 v_texture_coordinate_1;
varying vec4 v_texture_coordinate_2;
varying vec4 v_texture_coordinate_3;
varying vec4 v_texture_coordinate_4;
varying vec4 v_texture_coordinate_5;
varying vec4 v_texture_coordinate_6;
varying vec4 v_texture_coordinate_7;

    const float coef = 2.0;
	const float threshold = 10.0;
    const float y_weight = 48.0;
    const float u_weight = 7.0;
    const float v_weight = 6.0;

    const mat3 yuv = mat3(0.299, 0.587, 0.114, -0.169, -0.331, 0.499, 0.499, -0.418, -0.0813);
    const mat3 yuv_weighted = mat3(y_weight * yuv[0], u_weight * yuv[1], v_weight * yuv[2]);

    vec4 RGBtoYUV(vec3 v0, vec3 v1, vec3 v2, vec3 v3) {
      float a = yuv_weighted[0].x * v0.x + yuv_weighted[0].y * v0.y + yuv_weighted[0].z * v0.z;
      float b = yuv_weighted[0].x * v1.x + yuv_weighted[0].y * v1.y + yuv_weighted[0].z * v1.z;
      float c = yuv_weighted[0].x * v2.x + yuv_weighted[0].y * v2.y + yuv_weighted[0].z * v2.z;
      float d = yuv_weighted[0].x * v3.x + yuv_weighted[0].y * v3.y + yuv_weighted[0].z * v3.z;

      return vec4(a, b, c, d);
    }

    bvec4 _and_(bvec4 A, bvec4 B) {
      return bvec4(A.x && B.x, A.y && B.y, A.z && B.z, A.w && B.w);
    }

    bvec4 _or_(bvec4 A, bvec4 B) {
      return bvec4(A.x || B.x, A.y || B.y, A.z || B.z, A.w || B.w);
    } 

    vec4 df(vec4 A, vec4 B) {
      return vec4(abs(A - B));
    }
	
	bvec4 close(vec4 A, vec4 B) {
      return (lessThan(df(A, B), vec4(10.0, 10.0, 10.0, 10.0)));
    }
    bvec4 eq2(vec4 A, vec4 B)
    {
    return (lessThan(df(A, B), vec4(2.0, 2.0, 2.0, 2.0)));
    }

	float c_df(vec3 c1, vec3 c2) {
                        vec3 df = abs(c1 - c2);
                        return df.r + df.g + df.b;
                }

    vec4 weighted_distance(vec4 a, vec4 b, vec4 c, vec4 d, vec4 e, vec4 f, vec4 g, vec4 h) {
      return (df(a, b) + df(a, c) + df(d, e) + df(d, f) + 4.0 * df(g, h));
    }
	

    void main() {
      vec2 fp = fract(v_texture_coordinate.xy * vec2(resX, resY));

      vec3 A1 = texture2D(uTex, v_texture_coordinate_1.xw).rgb;
      vec3 B1 = texture2D(uTex, v_texture_coordinate_1.yw).rgb;
      vec3 C1 = texture2D(uTex, v_texture_coordinate_1.zw).rgb;

      vec3 A  = texture2D(uTex, v_texture_coordinate_2.xw).rgb;
      vec3 B  = texture2D(uTex, v_texture_coordinate_2.yw).rgb;
      vec3 C  = texture2D(uTex, v_texture_coordinate_2.zw).rgb;

      vec3 D  = texture2D(uTex, v_texture_coordinate_3.xw).rgb;
      vec3 E  = texture2D(uTex, v_texture_coordinate_3.yw).rgb;
      vec3 F  = texture2D(uTex, v_texture_coordinate_3.zw).rgb;

      vec3 G  = texture2D(uTex, v_texture_coordinate_4.xw).rgb;
      vec3 H  = texture2D(uTex, v_texture_coordinate_4.yw).rgb;
      vec3 I  = texture2D(uTex, v_texture_coordinate_4.zw).rgb;

      vec3 G5 = texture2D(uTex, v_texture_coordinate_5.xw).rgb;
      vec3 H5 = texture2D(uTex, v_texture_coordinate_5.yw).rgb;
      vec3 I5 = texture2D(uTex, v_texture_coordinate_5.zw).rgb;

      vec3 A0 = texture2D(uTex, v_texture_coordinate_6.xy).rgb;
      vec3 D0 = texture2D(uTex, v_texture_coordinate_6.xz).rgb;
      vec3 G0 = texture2D(uTex, v_texture_coordinate_6.xw).rgb;

      vec3 C4 = texture2D(uTex, v_texture_coordinate_7.xy).rgb;
      vec3 F4 = texture2D(uTex, v_texture_coordinate_7.xz).rgb;
      vec3 I4 = texture2D(uTex, v_texture_coordinate_7.xw).rgb;

      vec4 b = RGBtoYUV(B, D, H, F);
      vec4 c = RGBtoYUV(C, A, G, I);
      vec4 e = RGBtoYUV(E, E, E, E);
      vec4 d = b.yzwx;
      vec4 f = b.wxyz;
      vec4 g = c.zwxy;
      vec4 h = b.zwxy;
      vec4 i = c.wxyz;

      vec4 i4 = RGBtoYUV(I4, C1, A0, G5);
      vec4 i5 = RGBtoYUV(I5, C4, A1, G0);
      vec4 h5 = RGBtoYUV(H5, F4, B1, D0);
      vec4 f4 = h5.yzwx;
	  
      vec4 c1 = i4.yzwx;
      vec4 g0 = i5.wxyz;
      vec4 b1 = h5.zwxy;
      vec4 d0 = h5.wxyz;
	  
      vec4 Ao = vec4( 1.0, -1.0, -1.0,  1.0 );
      vec4 Bo = vec4( 1.0,  1.0, -1.0, -1.0 );
      vec4 Co = vec4( 1.5,  0.5, -0.5,  0.5 );
      vec4 Ax = vec4( 1.0, -1.0, -1.0,  1.0 );
      vec4 Bx = vec4( 0.5,  2.0, -0.5, -2.0 );
      vec4 Cx = vec4( 1.0,  1.0, -0.5,  0.0 );
      vec4 Ay = vec4( 1.0, -1.0, -1.0,  1.0 );
      vec4 By = vec4( 2.0,  0.5, -2.0, -0.5 );
      vec4 Cy = vec4( 2.0,  0.0, -1.0,  0.5 );

      vec4 Az = vec4( 6.0, -2.0, -6.0, 2.0 );
      vec4 Bz = vec4( 2.0, 6.0, -2.0, -6.0 );
      vec4 Cz = vec4( 5.0, 3.0, -3.0, -1.0 );
      vec4 Aw = vec4( 2.0, -6.0, -2.0, 6.0 );
      vec4 Bw = vec4( 6.0, 2.0, -6.0,-2.0 );
      vec4 Cw = vec4( 5.0, -1.0, -3.0, 3.0 );

      // These inequations define the line below which interpolation occurs
      bvec4 fx       = greaterThan(Ao * fp.y + Bo * fp.x, Co); 
      bvec4 fx_left  = greaterThan(Ax * fp.y + Bx * fp.x, Cx);
      bvec4 fx_up    = greaterThan(Ay * fp.y + By * fp.x, Cy);
      bvec4 fx3_left = greaterThan(Az * fp.y + Bz * fp.x, Cz);
      bvec4 fx3_up   = greaterThan(Aw * fp.y + Bw * fp.x, Cw);
	  
     // bvec4 t1 = _and_( notEqual(e, f), notEqual(e, h) );
     // bvec4 t2 = _and_( not(close(f, b)), not(close(h, d)));
     // bvec4 t3 = _and_( not(close(f, i4)), not(close(h, i5)));
     // bvec4 t4 = _or_( close(e, g), close(e, c) );
     // bvec4 t5 = _and_( close(e, i), _or_(t3, t4) );
     // bvec4 t6 = _and_( notEqual(f, f4), notEqual(f, i));
     // bvec4 t7 = _and_( notEqual(h, h5), notEqual(h, i));
     // bvec4 t8 = _or_( notEqual(h, g), notEqual(f, c));
     // bvec4 t9 = _and_( close(b, c1), close(d, g0));
	 // bvec4 t10 = _or_(t2, t5);
	 // bvec4 t11 = _or_(_or_(t6, t7), _or_(t8, t9));
	 // bvec4 interp_restriction_lv1 = _and_(t1, _and_(t10, t11));
	  
      bvec4 t1 = _and_( notEqual(e, f), notEqual(e, h) );
      bvec4 t2 = _and_( not(close(f, b)), not(close(h, d)) );
      bvec4 t3 = _and_( not(close(h, i4)), not(close(h, i5)) );
      bvec4 t4 = _and_( notEqual(f, f4), notEqual(f, i) );
      bvec4 t5 = _and_( notEqual(h, h5), notEqual(h, i) );
      bvec4 t6 = _and_( close(e, i), _or_(t4, t5) );
      bvec4 t7 = _or_( close(e, g), close(e, c) );
      bvec4 t8 = _and_( close(b, c1), close(d, g0));
	  bvec4 t9 = _or_( notEqual(h, g), notEqual(f, c));
      bvec4 interp_restriction_lv1 = _and_( t1, _or_(_or_(_or_( _or_( _or_(t2, t3), t6 ), t7 ), t8), t9 ));
	  
      bvec4 interp_restriction_lv2_left = _and_( notEqual(e, g), notEqual(d, g) );
      bvec4 interp_restriction_lv2_up   = _and_( notEqual(e, c), notEqual(b, c) );
      bvec4 interp_restriction_lv3_left = _and_( eq2(g,g0), not(eq2(d0,g0)) );
      bvec4 interp_restriction_lv3_up   = _and_( eq2(c,c1), not(eq2(b1,c1)) );
	  
      bvec4 edr      = _and_( lessThan(weighted_distance(e, c, g, i, h5, f4, h, f), 
                                       weighted_distance(h, d, i5, f, i4, b, e, i)), interp_restriction_lv1 );
      bvec4 edr_left = _and_( lessThanEqual(coef * df(f, g), df(h, c)), interp_restriction_lv2_left );
      bvec4 edr_up   = _and_( greaterThanEqual(df(f, g), coef * df(h, c)), interp_restriction_lv2_up );
      bvec4 edr3_left = interp_restriction_lv3_left;
      bvec4 edr3_up = interp_restriction_lv3_up;


	  
	  bvec4 t13 = _or_(fx_left, _and_(edr3_left, fx3_left));
	  bvec4 t14 = _or_(fx_up, _and_(edr3_up, fx3_up));
	  bvec4 nc = _and_(edr, _or_(fx,  _or_(_and_(edr_left, t13), _and_(edr_up, t14))));

      bvec4 px = lessThanEqual(df(e, f), df(e, h));

      vec3 res1 = nc.x ? px.x ? F : H : nc.y ? px.y ? B : F : nc.z ? px.z ? D : B : nc.w ? px.w ? H : D : E;
      vec3 res2 = nc.w ? px.w ? H : D : nc.z ? px.z ? D : B : nc.y ? px.y ? B : F : nc.x ? px.x ? F : H : E;

      vec3 res = mix(res1, res2, step(c_df(E, res1), c_df(E, res2)));

      gl_FragColor.xyz = res;
    }
