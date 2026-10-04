/* Input */
uniform mat4 u_MVPMatrix;   /* A constant representing the combined model/view/projection matrix */
attribute vec2 a_Position;  /* Per-vertex position information - DKS: Note I changed this from 3D to 2D */
attribute vec4 a_Color;     /* Per-vertex color information */
/* Output */
varying vec4 v_Color;       /* This will be passed into the fragment shader. */

void main()
{
    /* Send the color to the fragment shader */
    v_Color = a_Color;
    /* gl_Position is a special variable used to store the final position. */
    /* Multiply the vertex by the matrix to get the final point in normalized screen coordinates. */
    gl_Position = u_MVPMatrix * vec4(a_Position, 0.0, 1.0); /* DKS: Note I changed a_Position from 3D to 2D */
}
