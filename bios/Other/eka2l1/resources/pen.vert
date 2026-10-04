// Based on: https://stackoverflow.com/questions/6017176/gllinestipple-deprecated-in-opengl-3-1
// Thanks rabbid76!

#version 140

in vec2 in_position;

uniform mat4 u_proj;
uniform mat4 u_model;
uniform float u_pointSize;

flat out vec2 out_lineStartingPoint;
out vec2 out_lineCurrentProcessingPoint;

void main() {
    gl_Position = u_proj * u_model * vec4(in_position, 0.0, 1.0);
    gl_Position.y = -gl_Position.y;
    gl_PointSize = u_pointSize;

    // Flat will keep the original value non-interpolated, and the other one will be interpolated
    // and will give out current position of fragment processing.
    out_lineStartingPoint = gl_Position.xy / gl_Position.w;
    out_lineCurrentProcessingPoint = out_lineStartingPoint;
}