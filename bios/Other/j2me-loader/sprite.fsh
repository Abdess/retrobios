precision mediump float;
uniform vec2 uTexSize;
uniform sampler2D uTexUnit;
uniform vec3 uColorKey;
uniform bool uIsTransparency;
varying vec2 vTexture;

const vec3 COLORKEY_ERROR = vec3(0.5 / 255.0);

void main() {
#ifdef FILTER
    vec4 color = texture2D(uTexUnit, vTexture / uTexSize);
#else
    vec4 color = texture2D(uTexUnit, (floor(vTexture) + 0.5) / uTexSize);
#endif
    if (uIsTransparency && all(lessThan(abs(color.rgb - uColorKey), COLORKEY_ERROR)))
            discard;
    gl_FragColor = vec4(color.rgb, 1.0);
}