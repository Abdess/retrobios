/*
Nuance generic vertex shader for all pixel modes:

This vertex shader simply passes in the texture coordinates set by
glMultiTexCoord and then sets gl_Position with the transformed vertex
coordinate.
*/

void main(void) 
{
  gl_TexCoord[0] = gl_MultiTexCoord0;
  gl_TexCoord[1] = gl_MultiTexCoord1;
  gl_TexCoord[2] = gl_MultiTexCoord2;
  gl_Position = gl_ModelViewProjectionMatrix * gl_Vertex;
}