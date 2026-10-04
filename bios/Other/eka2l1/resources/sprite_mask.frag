#version 140

uniform sampler2D u_tex;
uniform sampler2D u_mask;
uniform float u_invert;
uniform float u_flat;
uniform vec4 u_color;
uniform float u_flip;

in vec2 r_texcoord;
out vec4 o_color;

void main() {
    vec4 maskValue = texture(u_mask, r_texcoord);
    maskValue = mix(maskValue, vec4(1.0) - maskValue, vec4(u_invert));

    vec4 colorOriginal = texture(u_tex, r_texcoord) * (u_color / 255.0);
    colorOriginal.a = mix(maskValue.r, 1.0 - step(maskValue.r, 0.0), step(1.0, u_flat));

    o_color = colorOriginal;
}