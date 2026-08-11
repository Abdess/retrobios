uniform mat4 uMatrix;
uniform mat4 uMatrixMV;
uniform vec3 uColor;
uniform float uAmbIntensity;
uniform bool uIsPrimitive;
attribute vec4 aPosition;
attribute vec3 aNormal;
attribute vec3 aColorData;
attribute vec2 aMaterial;
varying vec3 vColor;
varying vec3 vNormal;
varying float vIsReflect;
varying float vAmbIntensity;

const float COLOR_UNIT = 1.0 / 255.0;
void main() {
    gl_Position = uMatrix * aPosition;
    vNormal = mat3(uMatrixMV) * aNormal;
    if (uIsPrimitive) {
        vColor = uColor.r < -0.5 ? vec3(aColorData * COLOR_UNIT) : uColor;
        vIsReflect = 1.0;
        vAmbIntensity = uAmbIntensity;
    } else {
        vColor = vec3(aColorData * COLOR_UNIT);
        vIsReflect = aMaterial[1];
        vAmbIntensity = aMaterial[0] > 0.5 ? uAmbIntensity : -1.0;
    }
}