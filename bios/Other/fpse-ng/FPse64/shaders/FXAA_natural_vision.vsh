attribute highp vec2 aVertex;
attribute highp vec2 aTexCoord;
varying mediump vec2 vTexCoord;
void main(){
   gl_Position = vec4(aVertex.x, aVertex.y, 0.0, 1.0);
   vTexCoord = aTexCoord;
}