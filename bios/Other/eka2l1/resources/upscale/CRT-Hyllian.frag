/*
   Hyllian's CRT Shader
  
   Copyright (C) 2011-2016 Hyllian - sergiogdb@gmail.com

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.

*/ 

#ifdef GL_ES
precision mediump float;
precision mediump int;
#endif

uniform sampler2D sampler0;
in vec2 r_texcoord;


uniform vec2 u_texelDelta;
uniform vec2 u_pixelDelta; 

out vec4 o_color;


const vec2 rubyTextureSize = vec2(480.0,272.0);
const vec2 rubyInputSize = vec2(480.0,272.0);


#define SATURATION 1.0
#define PHOSPHOR 1.0
#define VSCANLINES 0.0
#define InputGamma 2.5
#define OutputGamma 2.3
#define SHARPNESS 1.0
#define COLOR_BOOST 1.4
#define RED_BOOST 1.0
#define GREEN_BOOST 1.0
#define BLUE_BOOST 1.0
#define SCANLINES_STRENGTH 0.60
#define BEAM_MIN_WIDTH 0.80
#define BEAM_MAX_WIDTH 0.95
#define CRT_ANTI_RINGING 0.8  

#define GAMMA_IN(color)     pow(color, vec4(InputGamma, InputGamma, InputGamma, InputGamma))
#define GAMMA_OUT(color)    pow(color, vec4(1.0 / OutputGamma, 1.0 / OutputGamma, 1.0 / OutputGamma, 1.0 / OutputGamma))


// Horizontal cubic filter.

// Some known filters use these values:

//    B = 0.0, C = 0.0  =>  Hermite cubic filter.
//    B = 1.0, C = 0.0  =>  Cubic B-Spline filter.
//    B = 0.0, C = 0.5  =>  Catmull-Rom Spline filter. This is the default used in this shader.
//    B = C = 1.0/3.0   =>  Mitchell-Netravali cubic filter.
//    B = 0.3782, C = 0.3109  =>  Robidoux filter.
//    B = 0.2620, C = 0.3690  =>  Robidoux Sharp filter.
//    B = 0.36, C = 0.28  =>  My best config for ringing elimination in pixel art (Hyllian).


// For more info, see: http://www.imagemagick.org/Usage/img_diagrams/cubic_survey.gif

// Change these params to configure the horizontal filter.
const float  B =  0.0; 
const float  C =  0.5;  

mat4 invX = mat4(            (-B - 6.0*C)/6.0,         (3.0*B + 12.0*C)/6.0,     (-3.0*B - 6.0*C)/6.0,             B/6.0,
                                        (12.0 - 9.0*B - 6.0*C)/6.0, (-18.0 + 12.0*B + 6.0*C)/6.0,                      0.0, (6.0 - 2.0*B)/6.0,
                                       -(12.0 - 9.0*B - 6.0*C)/6.0, (18.0 - 15.0*B - 12.0*C)/6.0,      (3.0*B + 6.0*C)/6.0,             B/6.0,
                                                   (B + 6.0*C)/6.0,                           -C,                      0.0,               0.0); 
 

void main()
{
    vec2 OGL2bPos = (r_texcoord + vec2(0.000001)) * (1.0/u_pixelDelta.xy);
    vec4 color;
	
    vec2 TextureSize = vec2(SHARPNESS*rubyTextureSize.x, rubyTextureSize.y);

    vec2 dx = mix(vec2(1.0/TextureSize.x, 0.0), vec2(0.0, 1.0/TextureSize.y), VSCANLINES);
    vec2 dy = mix(vec2(0.0, 1.0/TextureSize.y), vec2(1.0/TextureSize.x, 0.0), VSCANLINES);

    vec2 pix_coord = r_texcoord*TextureSize + vec2(-0.5, 0.5);

    vec2 tc = mix((floor(pix_coord) + vec2(0.5, 0.5))/TextureSize, (floor(pix_coord) + vec2(1.0, -0.5))/TextureSize, VSCANLINES);

    vec2 fp = mix(fract(pix_coord), fract(pix_coord.yx), VSCANLINES);

    vec4 c00 = GAMMA_IN(texture(sampler0, tc     - dx - dy));
    vec4 c01 = GAMMA_IN(texture(sampler0, tc          - dy));
    vec4 c02 = GAMMA_IN(texture(sampler0, tc     + dx - dy));
    vec4 c03 = GAMMA_IN(texture(sampler0, tc + 2.0*dx - dy));
    vec4 c10 = GAMMA_IN(texture(sampler0, tc     - dx     ));
    vec4 c11 = GAMMA_IN(texture(sampler0, tc              ));
    vec4 c12 = GAMMA_IN(texture(sampler0, tc     + dx     ));
    vec4 c13 = GAMMA_IN(texture(sampler0, tc + 2.0*dx     ));

    // Get min/max samples
    vec4 min_sample = min(min(c01, c11), min(c02, c12));
    vec4 max_sample = max(max(c01, c11), max(c02, c12));

    mat4 color_matrix0 = mat4(c00, c01, c02, c03);
    mat4 color_matrix1 = mat4(c10, c11, c12, c13);
    
    vec4 invX_Px    = vec4(fp.x*fp.x*fp.x, fp.x*fp.x, fp.x, 1.0) * invX;
    vec4 color0     = color_matrix0 * invX_Px;
    vec4 color1     = color_matrix1 * invX_Px;

    // Anti-ringing
    vec4 aux    = color0;
    color0      = clamp(color0, min_sample, max_sample);
    color0      = mix(aux, color0, CRT_ANTI_RINGING);
    aux         = color1;
    color1      = clamp(color1, min_sample, max_sample);
    color1      = mix(aux, color1, CRT_ANTI_RINGING);

    float pos0 = fp.y;
    float pos1 = 1.0 - fp.y;

    vec4 lum0 = mix(vec4(BEAM_MIN_WIDTH), vec4(BEAM_MAX_WIDTH), color0);
    vec4 lum1 = mix(vec4(BEAM_MIN_WIDTH), vec4(BEAM_MAX_WIDTH), color1);

    vec4 d0 = clamp(pos0/(lum0 + 0.0000001), 0.0, 1.0);
    vec4 d1 = clamp(pos1/(lum1 + 0.0000001), 0.0, 1.0);

    d0 = exp(-10.0*SCANLINES_STRENGTH*d0*d0);
    d1 = exp(-10.0*SCANLINES_STRENGTH*d1*d1);

    color = clamp(color0*d0 + color1*d1, 0.0, 1.0);            

    color *= COLOR_BOOST*vec4(RED_BOOST, GREEN_BOOST, BLUE_BOOST, 1.0);

    float mod_factor = mix(OGL2bPos.x, OGL2bPos.y, VSCANLINES);

    vec4 dotMaskWeights = mix(
        vec4(1.0, 0.7, 1.0, 0.0),
        vec4(0.7, 1.0, 0.7, 0.0),
        floor(mod(mod_factor, 2.0))
    );

    color*= mix(vec4(1.0), dotMaskWeights, PHOSPHOR);

    color  = GAMMA_OUT(color);

	float l = length(color);
	color = normalize(pow(color, vec4(SATURATION)))*l;		
	
    o_color = color; 
}
