precision mediump float;
uniform sampler2D uTextureUnit;
uniform sampler2D uSphereUnit;
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

void main() {
    vec4 color = texture2D(uTextureUnit, vTexture);
    if (vIsTransparency > 0.5 && color.a < 0.5) {
        discard;
    }
    if (vAmbIntensity < -0.5) {
        gl_FragColor = vec4(color.rgb, 1.0);
        return;
    }
    float lambert_factor = max(dot(normalize(vNormal), uLightDir), 0.0);
    float light = min(vAmbIntensity + uDirIntensity * lambert_factor, 1.0);
    if (uToonThreshold > -0.5) {
        light = light < uToonThreshold ? uToonLow : uToonHigh;
    }
    color.rgb *= light;
    if (uSphereSize.x > -0.5 && vIsReflect > 0.5) {
        color.rgb += texture2D(uSphereUnit, (vNormal.xy / 128.0 + 32.0) / uSphereSize).rgb;
    }
    gl_FragColor = vec4(color.rgb, 1.0);
}