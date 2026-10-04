#version 140

uniform vec4 u_color;
out vec4 o_color;

void main() {
    o_color = (u_color / 255.0);
}