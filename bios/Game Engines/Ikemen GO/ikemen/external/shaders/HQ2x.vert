#if __VERSION__ >= 450
	// VULKAN PATH
	layout(push_constant, std430) uniform u {
		vec2 TextureSize;
	};
	layout(location = 0) in vec2 VertCoord;
	layout(location = 0) out vec4 TexCoord[7];
#else
	// OPENGL / GLES PATH
	uniform vec2 TextureSize;
	in vec2 VertCoord;
	out vec4 TexCoord[7];
#endif

void main() {
	gl_Position = vec4(VertCoord, 0.0, 1.0);
	vec2 texCoord = (VertCoord + 1.0) / 2.0;
	float x = 0.5 * (1.0 / TextureSize.x);
	float y = 0.5 * (1.0 / TextureSize.y);
	vec2 dg1 = vec2(x, y);
	vec2 dg2 = vec2(-x, y);
	vec2 dx  = vec2(x, 0.0);
	vec2 dy  = vec2(0.0, y);

	TexCoord[0].xy = texCoord;
	TexCoord[1].xy = texCoord - dg1;
	TexCoord[1].zw = texCoord - dy;
	TexCoord[2].xy = texCoord - dg2;
	TexCoord[2].zw = texCoord + dx;
	TexCoord[3].xy = texCoord + dg1;
	TexCoord[3].zw = texCoord + dy;
	TexCoord[4].xy = texCoord + dg2;
	TexCoord[4].zw = texCoord - dx;
}
