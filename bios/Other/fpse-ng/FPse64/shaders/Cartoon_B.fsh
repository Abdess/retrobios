precision mediump float;
uniform sampler2D uTex;
uniform lowp float resX;       
uniform lowp float resY;       
varying vec2 vTexCoord;
const float th = 0.15;
const float bb = 1.50;
const float pp = 1.55;
const float cl = 7.00;
void main()
{
	vec2 stp0 = vec2(resX, 0.);
	vec2 st0p = vec2(0., resY);
	vec3 ct = 	texture2D(uTex, vTexCoord).rgb;
	vec3 lx =  texture2D(uTex, vTexCoord-stp0).rgb;
	vec3 rx =  texture2D(uTex, vTexCoord+stp0).rgb;
	vec3 uy =  texture2D(uTex, vTexCoord-st0p).rgb;
	vec3 dy =  texture2D(uTex, vTexCoord+st0p).rgb;
   vec3 dt = vec3(1.0,1.0,1.0);
	float d1 = 2.5*dot(abs(lx-rx),dt)/(dot(lx+rx,dt)+0.50);
	float d2 = 2.5*dot(abs(uy-dy),dt)/(dot(uy+dy,dt)+0.50);
	float d  = d1 + d2;
   float l = cl*length(ct)/1.73;
   float p = floor(l); 
   float v = fract(l); 
   float t = (p==0.0)?0.6:0.33;
   v = 0.6*(max(v-1.0+t,0.0))/t; 
   v = 1.73*(p+v)/cl + 0.05;
	gl_FragColor = vec4(clamp((1.12-bb*pow(max(d-th,0.0),pp))*v*normalize(ct),0.,1.), 1.);
}