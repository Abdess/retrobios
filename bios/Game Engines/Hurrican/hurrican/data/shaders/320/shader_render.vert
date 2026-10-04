/* Input */
uniform mat4 u_MVPMatrix;   /* A constant representing the combined model/view/projection matrix. */
in vec2 a_Position;  /* Per-vertex position information - DKS: Note I changed this from 3D to 2D */
in vec4 a_Color;     /* Per-vertex color information */
in vec2 a_Texcoord0; /* Per-vertex texcoord information */
/* Output */
out vec4 v_Color;       /* This will be passed into the fragment shader. */
out vec2 v_Texcoord0;

void main()
{
    /* Send the color to the fragment shader */
    v_Color = a_Color;
    /* Send the texcoords to the fragment shader */
    v_Texcoord0 = a_Texcoord0;
    /* gl_Position is a special variable used to store the final position. */
    /* Multiply the vertex by the matrix to get the final point in normalized screen coordinates. */
    gl_Position = u_MVPMatrix * vec4(a_Position, 0.0f, 1.0f); /* DKS: Note I changed a_Position from 3D to 2D */
}
