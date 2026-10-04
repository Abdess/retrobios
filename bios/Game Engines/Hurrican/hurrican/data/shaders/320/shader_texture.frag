/* Input */
in vec4 v_Color;
in vec2 v_Texcoord0;
uniform sampler2D u_Texture0;
/* Output */
out vec4 v_FragColor;

void main()
{
    /* Sample the current texture */
    v_FragColor = texture( u_Texture0, v_Texcoord0 ) * v_Color;
}
