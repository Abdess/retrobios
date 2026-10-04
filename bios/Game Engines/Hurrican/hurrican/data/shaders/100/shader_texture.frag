/* Input */
varying vec4 v_Color;
varying vec2 v_Texcoord0;
uniform sampler2D u_Texture0;

void main()
{
    /* Sample the current texture */
    gl_FragColor = texture2D( u_Texture0, v_Texcoord0 ) * v_Color;
}

