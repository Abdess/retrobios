precision mediump float;
uniform sampler2D uTextureUnit;
uniform sampler2D uSphereUnit;
uniform vec2 uTexSize;
uniform vec3 uColorKey;
uniform vec2 uSphereSize;
uniform vec3 uLightDir;
uniform float uDirIntensity;
uniform float uToonThreshold;
uniform float uToonHigh;
uniform float uToonLow;
varying vec2 vTexture;
varying vec3 vNormal;
varying float vIsTransparency;
varying float vIsReflect;
varying float vAmbIntensity;

const vec3 COLORKEY_ERROR = vec3(0.5 / 255.0);

void main() {
#ifdef FILTER
    vec4 color = texture2D(uTextureUnit, vTexture / uTexSize);
#else
    vec4 color = texture2D(uTextureUnit, (floor(vTexture) + 0.5) / uTexSize);
#endif
    if (vIsTransparency > 0.5 && all(lessThan(abs(color.rgb - uColorKey), COLORKEY_ERROR)))
            discard;
    if (vAmbIntensity < -0.5) {
        gl_FragColor = vec4(color.rgb, 1.0);
        return;
    }
    vec4 spec = uSphereSize.x < -0.5 || vIsReflect < 0.5 ?
        vec4(0.0) : texture2D(uSphereUnit, (normalize(vNormal).xy + 1.0) * 0.5 * uSphereSize);
    float lambert_factor = max(dot(normalize(vNormal), uLightDir), 0.0);
    float light = min(vAmbIntensity + uDirIntensity * lambert_factor, 1.0);
    if (uToonThreshold > -0.5) {
        light = light < uToonThreshold ? uToonLow : uToonHigh;
    }
    gl_FragColor = vec4(color.rgb * light + spec.rgb, 1.0);
}