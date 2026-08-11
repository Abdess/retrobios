precision mediump float;
uniform sampler2D uTextureUnit;
uniform bool uIsTransparency;
varying vec2 vTexture;

void main() {
    vec4 color = texture2D(uTextureUnit, vTexture);
    if (uIsTransparency && color.a < 0.5) {
        discard;
    }
    gl_FragColor = vec4(color.rgb, 1.0);
}