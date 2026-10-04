#if __VERSION__ >= 450
	// VULKAN PATH
	layout(push_constant, std430) uniform u {
		vec2 TextureSize;
	};
	layout(location = 0) in vec2 VertCoord;
	layout(location = 0) out vec3 vTexCoord;
#else
	// OPENGL / GLES PATH
	uniform vec2 TextureSize;
	in vec2 VertCoord;
	out vec3 vTexCoord;
#endif

void main() {
    gl_Position = vec4(VertCoord, 0.0, 1.0);
    vTexCoord = vec3((VertCoord + 1.0) / 2.0, 0.0);
}