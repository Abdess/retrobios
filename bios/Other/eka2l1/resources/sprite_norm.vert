#version 140

in vec2 in_position;
in vec2 in_texcoord;

out vec2 r_texcoord;
out vec4 r_color;

uniform mat4 u_proj;
uniform mat4 u_model;
uniform vec4 u_color;

void main() {
    gl_Position = u_proj * u_model * vec4(in_position, 0.0, 1.0);
    gl_Position.y = -gl_Position.y;

    r_texcoord = in_texcoord;
    r_color = u_color;
}