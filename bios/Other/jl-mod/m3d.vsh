uniform mat4 u_matrix;
attribute vec4 a_position;
attribute vec2 a_texcoord0;
varying vec2 v_texcoord0;

void main() {
    gl_Position = u_matrix * a_position;
    v_texcoord0 = a_texcoord0;
}
