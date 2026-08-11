precision mediump float;
uniform sampler2D uSphereUnit;
uniform vec2 uSphereSize;
uniform vec3 uLightDir;
uniform float uDirIntensity;
uniform float uToonThreshold;
uniform float uToonHigh;
uniform float uToonLow;
varying vec3 vColor;
varying vec3 vNormal;
varying float vIsReflect;
varying float vAmbIntensity;

void main() {
    if (vAmbIntensity < -0.5) {
        gl_FragColor = vec4(vColor, 1.0);
        return;
    }
    vec4 spec = uSphereSize.x < -0.5 || vIsReflect < 0.5 ?
        vec4(0.0) : texture2D(uSphereUnit, (normalize(vNormal).xy + 1.0) * 0.5 * uSphereSize);
    float lambert_factor = max(dot(normalize(vNormal), uLightDir), 0.0);
    float light = min(vAmbIntensity + uDirIntensity * lambert_factor, 1.0);
    if (uToonThreshold > -0.5) {
        light = light < uToonThreshold ? uToonLow : uToonHigh;
    }
    gl_FragColor = vec4(vColor * light + spec.rgb, 1.0);
}