//When converting to SPV, specify version 450
//#version 450 core

#if __VERSION__ >= 450
	// VULKAN PATH
	#define COMPAT_TEXTURE texture
	layout(binding = 1) uniform UniformBufferObject  {
		vec4 x1x2x4x3;
		vec4 tint;
		vec3 add;
		vec3 mult;
		float alpha, gray, hue;
		int mask;
		bool isFlat, isRgba, isTrapez, neg;
		float iTime;
		vec2 iResolution;
		float aspectRatio;
	};
	layout(push_constant, std430) uniform u {
		vec4 palUV;
		float p0, p1, p2, p3, p4, p5, p6, p7;
		float p8, p9, p10, p11, p12, p13, p14, p15;
	};
	layout(binding = 2) uniform sampler2D tex;
	layout(binding = 3) uniform sampler2D pal;
	layout(binding = 4) uniform sampler2D bgl_RenderedTexture; // GrabPass
	layout(location = 0) in vec2 texcoord;
	layout(location = 0) out vec4 FragColor;
#else
	// OPENGL / GLES PATH
	#define COMPAT_VARYING in
	#define COMPAT_TEXTURE texture
	#ifdef GL_ES
		precision highp float;
		precision highp int;
	#endif
	out vec4 FragColor;
	
	uniform sampler2D tex;
	uniform sampler2D pal;
	uniform sampler2D bgl_RenderedTexture; // GrabPass
	
	uniform vec4 x1x2x4x3;
	uniform vec4 tint;
	uniform vec3 add, mult;
	uniform float alpha, gray, hue;
	uniform int mask;
	uniform bool isFlat, isRgba, isTrapez, neg;

	uniform float p0, p1, p2, p3, p4, p5, p6, p7;
	uniform float p8, p9, p10, p11, p12, p13, p14, p15;

	uniform float iTime;
	uniform vec2 iResolution;
	uniform float aspectRatio;
	COMPAT_VARYING vec2 texcoord;
#endif
// ----------------------


vec2 wobble(vec2 uv, float amplitude, float frequence, float speed)
{
    float offset = amplitude * sin(uv.y * frequence + iTime * speed);
    return vec2(uv.x + offset, uv.y);	
}

void main() {
    // Obtain the UV coordinates of the entire screen (0.0 ~ 1.0)
    vec2 screen_uv = gl_FragCoord.xy / iResolution;

    //screen_uv.y = 1.0 - screen_uv.y;

    // Obtain the parameters passed from CNS (use default values ​​if not set)
    float amplitude = (p0 != 0.0) ? p0 : 0.0130;
    float frequence = (p1 != 0.0) ? p1 : 25.00;
    float speed     = (p2 != 0.0) ? p2 : 16.0;
	

    // Distort the background UV coordinates to create a wavy effect
    vec2 distorted_uv = wobble(screen_uv, amplitude/aspectRatio, frequence, speed);

    // Sample the GrabPassed background image (bgl_RenderedTexture) using the distorted UVs
    vec4 bgColor = texture(bgl_RenderedTexture, distorted_uv);
    bgColor.a = 1.0; 
    
    // Output to the screen
    FragColor = bgColor;

}