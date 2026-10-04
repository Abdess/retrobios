#version 140

in vec2 in_position;

uniform mat4 u_proj;
uniform mat4 u_model;

void main() {
    gl_Position = u_proj * u_model * vec4(in_position, 0.0, 1.0);
    gl_Position.y = -gl_Position.y;
}