uniform mat4 uMatrix;
uniform mat4 uMatrixMV;
uniform bool uIsTransparency;
uniform bool uIsPrimitive;
uniform float uAmbIntensity;
attribute vec4 aPosition;
attribute vec3 aNormal;
attribute vec2 aColorData;
attribute vec3 aMaterial;
varying vec2 vTexture;
varying vec3 vNormal;
varying float vIsTransparency;
varying float vIsReflect;
varying float vAmbIntensity;

void main() {
    gl_Position = uMatrix * aPosition;
    vNormal = mat3(uMatrixMV) * aNormal;
    if (uIsPrimitive) {
        vIsTransparency = uIsTransparency ? 1.0 : 0.0;
        vIsReflect = 1.0;
        vAmbIntensity = uAmbIntensity;
    } else {
        vIsTransparency = aMaterial[2];
        vIsReflect = aMaterial[1];
        vAmbIntensity = aMaterial[0] > 0.5 ? uAmbIntensity : -1.0;
    }
#ifdef FILTER
    vTexture = aColorData + 0.5;
#else
    vTexture = aColorData;
#endif
}