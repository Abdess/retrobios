precision mediump float;
uniform sampler2D sampler0;
varying vec2 v_texcoord0;
void main() {
    gl_FragColor = texture2D(sampler0, v_texcoord0);
}