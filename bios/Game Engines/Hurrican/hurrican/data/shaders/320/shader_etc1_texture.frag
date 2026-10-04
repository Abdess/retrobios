/* Input */
in vec4 v_Color;
in vec2 v_Texcoord0;
uniform sampler2D u_Texture0;
uniform sampler2D u_Texture1;
/* Output */
out vec4 v_FragColor;

void main()
{    
    /* Sample the current texture */    
    v_FragColor = vec4(texture( u_Texture0, v_Texcoord0 ).rgb, texture( u_Texture1, v_Texcoord0 ).r) * v_Color;
}
