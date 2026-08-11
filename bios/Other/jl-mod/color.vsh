uniform mat4 uMatrix;
uniform mat3 uNormalMatrix;
uniform float uAmbIntensity;
attribute vec4 aPosition;
attribute vec3 aNormal;
attribute vec3 aColorData;
attribute vec2 aMaterial;
varying vec3 vColor;
varying vec3 vNormal;
varying float vIsReflect;
varying float vAmbIntensity;

void main() {
    gl_Position = uMatrix * aPosition;
    vNormal = uNormalMatrix * aNormal;
    vColor = aColorData;
    vIsReflect = aMaterial[1];
    vAmbIntensity = aMaterial[0] > 0.5 ? uAmbIntensity : -1.0;
}