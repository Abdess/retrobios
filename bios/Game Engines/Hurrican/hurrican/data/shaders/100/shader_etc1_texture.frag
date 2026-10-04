/* Input */
varying vec4 v_Color;
varying vec2 v_Texcoord0;
uniform sampler2D u_Texture0;
uniform sampler2D u_Texture1;

void main()
{    
    /* Sample the current texture */    
    gl_FragColor = vec4(texture2D( u_Texture0, v_Texcoord0 ).rgb, texture2D( u_Texture1, v_Texcoord0 ).r) * v_Color;
}
