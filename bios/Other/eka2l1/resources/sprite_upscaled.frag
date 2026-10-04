#version 140

uniform sampler2D u_tex;
uniform vec4 u_color;

in vec2 r_texcoord;
out vec4 o_color;

void main() {
    o_color = texture(u_tex, r_texcoord) * (u_color / 255.0);
}