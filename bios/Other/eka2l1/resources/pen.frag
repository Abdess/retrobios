// Based on: https://stackoverflow.com/questions/6017176/gllinestipple-deprecated-in-opengl-3-1
// Thanks rabbid76!

#version 140

flat in vec2 out_lineStartingPoint;
in vec2 out_lineCurrentProcessingPoint;

uniform vec4 u_color;
uniform uint u_pattern;
uniform vec2 u_viewport;

out vec4 o_color;

void main() {
    vec2 dirvec = (out_lineCurrentProcessingPoint - out_lineStartingPoint) * u_viewport;
    float dist = length(dirvec);

    uint bit_in_pattern = uint(round(dist)) & 15U;
    uint bit_mask = 1U << bit_in_pattern;

    if ((u_pattern & bit_mask) == 0U)
        discard;

    o_color = u_color / 255.0;
}