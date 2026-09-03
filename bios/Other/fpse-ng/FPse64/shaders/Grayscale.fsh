precision mediump float;
varying vec2 vTexCoord;
uniform sampler2D uTex;

void main()
{
	vec4 fragColor = texture2D(uTex, vTexCoord);
	gl_FragColor = vec4(dot(fragColor, vec4(0.299, 0.587, 0.114, 0.0)));
}
