!!ARBfp1.0

PARAM val00 = 1.2;
PARAM RGBtoY = { 0.299, 0.587, 0.114, 0};
PARAM RGBtoI = { 0.596,-0.275,-0.321, 0};
PARAM RGBtoQ = { 0.212,-0.523, 0.311, 0};
PARAM YIQtoR = { 1, 0.95568806036115671171, 0.61985809445637075388, 0};
PARAM YIQtoG = { 1,-0.27158179694405859326,-0.64687381613840131330, 0};
PARAM YIQtoB = { 1,-1.10817732668266195230, 1.70506455991918171490, 0};

TEMP c0, c1;

TEX c0, fragment.texcoord[0], texture[0], 2D;

TEX c1, fragment.texcoord[0].zyzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[0].xwzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[0].zwzw, texture[0], 2D;
MAD c0, c1, 0.125, c0;

TEX c1, fragment.texcoord[1], texture[0], 2D;
ADD c0, c1, c0;
TEX c1, fragment.texcoord[1].zyzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[1].xwzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[1].zwzw, texture[0], 2D;
MAD c0, c1, 0.125, c0;

TEX c1, fragment.texcoord[2], texture[0], 2D;
ADD c0, c1, c0;
TEX c1, fragment.texcoord[2].zyzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[2].xwzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[2].zwzw, texture[0], 2D;
MAD c0, c1, 0.125, c0;

TEX c1, fragment.texcoord[3], texture[0], 2D;
ADD c0, c1, c0;
TEX c1, fragment.texcoord[3].zyzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[3].xwzw, texture[0], 2D;
MAD c0, c1, 0.25, c0;
TEX c1, fragment.texcoord[3].zwzw, texture[0], 2D;
MAD c0, c1, 0.125, c0;

MUL c0, c0, 0.153846153846;

DP3 c1.x, c0, RGBtoY;
DP3 c1.y, c0, RGBtoI;
DP3 c1.z, c0, RGBtoQ;

POW c1.x, c1.x, val00.x;
MUL c1.yz, c1, val00;

DP3 c0.x, c1, YIQtoR;
DP3 c0.y, c1, YIQtoG;
DP3 c0.z, c1, YIQtoB;

MOV result.color, c0;
  
END
