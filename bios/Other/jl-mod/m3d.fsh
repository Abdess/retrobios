precision mediump float;

uniform sampler2D sampler0;
uniform vec4 u_color;
varying vec2 v_texcoord0;

void main() {
    gl_FragColor = v_texcoord0[0] < -0.5 ? u_color : texture2D(sampler0, v_texcoord0);
}
