/*
* MCE, the real life implementation of McEliece encryption scheme.
* Copyright Projet SECRET, INRIA, Rocquencourt and Bhaskar Biswas and 
* Nicolas Sendrier (Bhaskar.Biswas@inria.fr, Nicolas.Sendrier@inria.fr).
*
* This is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation; either version 2.1 of
* the License, or (at your option) any later version.
*
* This software is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this software; if not, write to the Free
* Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
* 02110-1301 USA, or see the FSF site: http://www.fsf.org.
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "buff.h"
#include "arith.h"
#include "precomp.h"

double round(double);
int l2(unsigned long x);

typedef struct elt {
  int * element;
  int taille, nombre;
  int pos;
  unsigned long valeur, maximum;
  struct elt * suivant;
} * liste_t;

liste_t liste_todo;
liste_t liste_inv;
int * aux;

liste_t liste_alloc(liste_t s) {
  liste_t l =  (liste_t) malloc(sizeof (struct elt));
  l->suivant = s;
  return l;
}

void liste_free(liste_t l) {
  if (l != NULL)
    liste_free(l->suivant);
  free(l);
}

int is_leaf(int m, int t) {
  static int feuille[6] = {7, 5, 4, 4, 3, 3};
  if (m < 6)
    return (t <= 32);
  else if (m > 16)
    return (t <= 1);
  else if (m > 11)
    return (t <= 2);
  else
    return (feuille[m - 6] >= t);
}

int max_bino[] = {0, 0, 0, 0, 0, 128, 64, 64, 32, 32, 32, 32, 32, 32, 32, 32, 32};
unsigned long * table_bino[] = {
  NULL, // 0
  NULL, // 1
  NULL, // 2
  NULL, // 3
  NULL, // 4
  (unsigned long [129]) { // 5
    0U, 0U, 0U, 0U, 0U, 1U, 6U, 21U, 56U, 126U, 252U, 462U, 792U,
    1287U, 2002U, 3003U, 4368U, 6188U, 8568U, 11628U, 15504U, 20349U,
    26334U, 33649U, 42504U, 53130U, 65780U, 80730U, 98280U, 118755U,
    142506U, 169911U, 201376U, 237336U, 278256U, 324632U, 376992U,
    435897U, 501942U, 575757U, 658008U, 749398U, 850668U, 962598U,
    1086008U, 1221759U, 1370754U, 1533939U, 1712304U, 1906884U,
    2118760U, 2349060U, 2598960U, 2869685U, 3162510U, 3478761U,
    3819816U, 4187106U, 4582116U, 5006386U, 5461512U, 5949147U,
    6471002U, 7028847U, 7624512U, 8259888U, 8936928U, 9657648U,
    10424128U, 11238513U, 12103014U, 13019909U, 13991544U, 15020334U,
    16108764U, 17259390U, 18474840U, 19757815U,21111090U, 22537515U,
    24040016U, 25621596U, 27285336U, 29034396U, 30872016U, 32801517U,
    34826302U, 36949857U,39175752U, 41507642U, 43949268U, 46504458U,
    49177128U, 51971283U, 54891018U, 57940519U, 61124064U,
    64446024U,67910864U, 71523144U, 75287520U, 79208745U, 83291670U,
    87541245U, 91962520U, 96560646U, 101340876U, 106308566U,
    111469176U, 116828271U, 122391522U, 128164707U, 134153712U,
    140364532U, 146803272U, 153476148U, 160389488U,167549733U,
    174963438U, 182637273U, 190578024U, 198792594U, 207288004U,
    216071394U, 225150024U, 234531275U, 244222650U, 254231775U,
    264566400U},
  (unsigned long [65]) { // 6
    0U, 0U, 0U, 0U, 0U, 0U, 1U, 7U, 28U, 84U, 210U, 462U, 924U, 1716U,
    3003U, 5005U, 8008U, 12376U, 18564U, 27132U, 38760U, 54264U,
    74613U, 100947U, 134596U, 177100U, 230230U, 296010U, 376740U,
    475020U, 593775U, 736281U, 906192U, 1107568U, 1344904U, 1623160U,
    1947792U, 2324784U, 2760681U, 3262623U, 3838380U, 4496388U,
    5245786U, 6096454U, 7059052U, 8145060U, 9366819U, 10737573U,
    12271512U, 13983816U, 15890700U, 18009460U, 20358520U, 22957480U,
    25827165U, 28989675U, 32468436U, 36288252U, 40475358U, 45057474U,
    50063860U, 55525372U, 61474519U, 67945521U,74974368U},
  (unsigned long [65]) { // 7
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 8U, 36U, 120U, 330U, 792U, 1716U,
    3432U, 6435U, 11440U, 19448U, 31824U, 50388U, 77520U, 116280U,
    170544U, 245157U, 346104U, 480700U, 657800U, 888030U, 1184040U,
    1560780U, 2035800U, 2629575U, 3365856U,4272048U, 5379616U,
    6724520U, 8347680U, 10295472U, 12620256U, 15380937U, 18643560U,
    22481940U, 26978328U, 32224114U, 38320568U, 45379620U, 53524680U,
    62891499U, 73629072U, 85900584U, 99884400U, 115775100U,
    133784560U, 154143080U, 177100560U, 202927725U, 231917400U,
    264385836U, 300674088U, 341149446U, 386206920U,
    436270780U,491796152U, 553270671U, 621216192U},
  (unsigned long [33]) { // 8
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 9U, 45U, 165U, 495U, 1287U,
    3003U, 6435U, 12870U, 24310U, 43758U, 75582U, 125970U, 203490U,
    319770U, 490314U, 735471U, 1081575U, 1562275U, 2220075U, 3108105U,
    4292145U, 5852925U, 7888725U, 10518300U},
  (unsigned long [33]) { // 9
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 10U, 55U, 220U, 715U,
    2002U, 5005U, 11440U, 24310U, 48620U, 92378U, 167960U, 293930U,
    497420U, 817190U, 1307504U, 2042975U, 3124550U, 4686825U,
    6906900U, 10015005U, 14307150U, 20160075U, 28048800U},
  (unsigned long [33]) { // 10
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 11U, 66U, 286U, 1001U,
    3003U, 8008U, 19448U, 43758U, 92378U, 184756U, 352716U,646646U,
    1144066U, 1961256U, 3268760U, 5311735U, 8436285U, 13123110U,
    20030010U, 30045015U, 44352165U, 64512240U},
  (unsigned long [33]) { // 11
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 12U, 78U, 364U,
    1365U, 4368U, 12376U, 31824U, 75582U, 167960U, 352716U, 705432U,
    1352078U, 2496144U, 4457400U, 7726160U, 13037895U, 21474180U,
    34597290U, 54627300U, 84672315U, 129024480U},
  (unsigned long [33]) { // 12
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 13U, 91U,
    455U, 1820U, 6188U, 18564U, 50388U, 125970U, 293930U, 646646U,
    1352078U, 2704156U, 5200300U, 9657700U, 17383860U, 30421755U,
    51895935U, 86493225U, 141120525U, 225792840U},
  (unsigned long [33]) { // 13
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 14U, 105U,
    560U, 2380U, 8568U, 27132U, 77520U, 203490U, 497420U, 1144066U,
    2496144U, 5200300U, 10400600U, 20058300U, 37442160U, 67863915U,
    119759850U, 206253075U, 347373600U},
  (unsigned long [33]) { // 14
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 15U,
    120U, 680U, 3060U, 11628U, 38760U, 116280U, 319770U, 817190U,
    1961256U, 4457400U, 9657700U, 20058300U, 40116600U, 77558760U,
    145422675U, 265182525U, 471435600U},
  (unsigned long [33]) { // 15
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U,
    16U, 136U, 816U, 3876U, 15504U, 54264U, 170544U, 490314U,
    1307504U, 3268760U, 7726160U, 17383860U, 37442160U, 77558760U,
    155117520U, 300540195U, 565722720U},
  (unsigned long [33]) { // 16
    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
    1U, 17U, 153U, 969U, 4845U, 20349U, 74613U, 245157U,
    735471U,2042975U, 5311735U, 13037895U, 30421755U, 67863915U,
    145422675U, 300540195U, 601080390U}};

unsigned long bino(int a, int b) {
  return table_bino[b][a];
}

unsigned long cw_coder(int * res, int t) {
  unsigned long x = 0;

  switch (t) {
  case 4:
    x = (res[3] * (res[3] - 1) * (res[3] - 2)) / 6;
    // calcul de binomial(res[3], 4). Il y a un risque de dépassement,
    // on peut avoir (res[3] - 3) * x > 2^32
    switch (x & 3) {
    case 0:
      x >>= 2;
      x *= res[3] - 3;
      break;
    case 1:
    case 3:
      x *= (res[3] - 3) >> 2;
      break;
    case 2:
      x >>= 1;
      x *= (res[3] - 3) >> 1;
      break;
    }
  case 3:
    x += ((unsigned long) (((res[2] * (res[2] - 1)) / 2) * (res[2] - 2))) / 3;
  case 2:
    x += ((unsigned long) (res[1] * (res[1] - 1))) / 2;
  case 1:
    x += res[0];
    break;
  default:
    x = table_bino[t][res[t - 1]] + cw_coder(res, t - 1);
    break;
  }

  return x;
}

// binomial(i,t) <= x < binomial(i+1,t)
// par recherche dichotomique
int inv_bino(unsigned long x, int t) {
  int debut, fin, milieu;

  debut = t - 1;
  fin = max_bino[t];
  milieu = (fin + debut) / 2;
  // invariants :
  // table_bino[t][debut] <= x < table_bino[t][fin]
  // debut <= milieu < fin
  // fin - milieu - 1 <= milieu - debut <= fin - milieu
  while (milieu > debut) {
    if (x < table_bino[t][milieu])
      fin = milieu;
    else
      debut = milieu;
    milieu = (fin + debut) / 2;
  }
  // milieu = debut
  // fin = debut + 1
  return debut;
}

void cw_decoder(unsigned long x, int t, int * res) {
  if (x == 0) {
    while (t > 0) {
      t--;
      res[t] = t;
    }
  }
  else if (t == 1) {
    res[0] = x;
  }
  else if (t == 2) {
    res[1] = round(sqrt(2 * x + 0.25));
    res[0] = x - (res[1] * (res[1] - 1)) / 2;
  }
  else if (t == 3) {
    unsigned long b;
    res[2] = 1 + cbrtf(6 * ((float) x)); // x > 0
    b = (res[2] * (res[2] - 1)) / 2; // binomial(res[2], 2)
    // par << chance >>, puisque res[2] <= 2^11, pas de dépassement
    // on a bien b * (res[2] - 2) < 2^32
    x -= (b * (res[2] - 2)) / 3; // binomial(res[2], 3)
    if (x >= b) { // on avait x >= binomial(res[2] + 1, 3)
      res[2]++;
      x -= b;
    }
    cw_decoder(x, 2, res);
  }
  else if (t == 4) {
    unsigned long b;
    res[3] = 1 + powf(24 * ((float) x), 0.25); // x > 0
    b = (res[3] * (res[3] - 1) * (res[3] - 2)) / 6; // binomial(res[3], 3)
    // calcul de binomial(res[3], 4). Il y a un risque de dépassement,
    // on peut avoir (res[3] - 3) * b > 2^32
    switch (b & 3) {
    case 0:
      x -= (b >> 2) * (res[3] - 3);
      break;
    case 1:
    case 3:
      x -= b * ((res[3] - 3) >> 2);
      break;
    case 2:
      x -= (b >> 1) * ((res[3] - 3) >> 1);
      break;
    }
    if (x >= b) { // on avait x >= binomial(res[3] + 1, 4)
      res[3]++;
      x -= b;
    }
    cw_decoder(x, 3, res);
  }
  else {
    res[t - 1] = inv_bino(x, t);
    cw_decoder(x - table_bino[t][res[t - 1]], t - 1, res);
  } 
}

int dicho_rec(int * cw, int i, int s, arith_t state, precomp_t p) {
  unsigned long u;
  int j, l, r;

  if (i == 0)
    return 0;

  if (i > (1 << s) - i) {
    int * cw2 = malloc(((1 << s) - i) * sizeof (int));
    r = cw[0] & (((unsigned long) -1) << s);
    for (j = 0, l = 0; (l < (1 << s) - i) && (j < i); ++r)
      if (cw[j] == r)
	++j;
      else {
	cw2[l] = r;
	++l;
      }
    for (; l < (1 << s) - i; ++l, ++r)
      cw2[l] = r;
    r = dicho_rec(cw2, l, s, state, p);
    free(cw2);
    return r;
  }

  if (i == 1) {
    liste_todo = liste_alloc(liste_todo);
    liste_todo->taille = s;
    liste_todo->nombre = 1;
    liste_todo->valeur = cw[0] & ((1 << s) - 1);
    liste_todo->maximum = 1 << s;
    return 0;
  }

  if (is_leaf(s, i)) {
    u = ~((-1) << s);
    for (j = 0; j < i; ++j)
      aux[j] = cw[j] & u;
    liste_todo = liste_alloc(liste_todo);
    liste_todo->nombre = i;
    liste_todo->valeur = cw_coder(aux, i);
    liste_todo->maximum = p.leaf_info[s][i].maximum;
    liste_todo->taille = p.leaf_info[s][i].deadbits;
    return 0;
  }

  for (l = 0; l < i; ++l)
    if (cw[l] & (1 << (s - 1)))
      break;
  r = coder(l, precomp_get_distrib(p, s, i), state);

#ifdef DEBUG
  printf("%d = %d + %d\n", i, l, i - l);
#endif

  r += dicho_rec(cw, l, s - 1, state, p);
  r += dicho_rec(cw + l, i - l, s - 1, state, p);

  return r;
}

// n la longueur max, à partir du (n+1)-eme, tous les bits sont nuls (ou ignorés)
int dicho(int * cw, arith_t state, precomp_t p) {
  int m, t, r, i, accel;
  liste_t l;

  m = p.m;
  t = p.t;

  aux = (int *) malloc((t + 1) * sizeof (int));
  liste_todo = NULL;

  r = dicho_rec(cw, t, m, state, p);

#ifdef DEBUG
  printf("%d\n", r);
  for (l = liste_todo; l != NULL; l = l->suivant)
    printf("%d\t%d\t%u\t%u\n", l->nombre, l->taille, l->maximum, l->valeur);
#endif

  // calcul du nombre i de bits réservés
  for (i = 0, l = liste_todo; l != NULL; l = l->suivant)
    i += l->taille;

  // On veut "réserver" i bits à la fin de state->buffer. Il
  // faut prendre en compte le codage arithmétique sachant que nous
  // devons avoir exactement la même action ici (au codage) que dans
  // dichoinv (au décodage).

  // cela est pris en compte à l'aide de verrous mis en place dans les
  // fonction de codage et de décodage
  accel = (bwrite_unlocked(state->buffer) >= i);

#ifdef DEBUG
  printf(accel ? "accel : oui\n" : "accel : non\n");
  printf("%d\t%d\n", bwrite_unlocked(state->buffer), i);
#endif

  if (accel)
    // les i derniers bits deviennent inaccessibles en écriture
    bwrite_decaler_fin(state->buffer, -i);

  for (l = liste_todo; l != NULL; l = l->suivant) {
    if (l->nombre > 1) {
      r += coder_uniforme(l->valeur >> l->taille, l->maximum, state);
      l->valeur &= ((1 << l->taille) - 1);
    }
  }

#ifdef DEBUG
  printf("%d\n", r);
#endif

  if (!accel) {
    for (l = liste_todo; l != NULL; l = l->suivant) {
      while (l->taille > PREC_PROBA) {
	l->taille -= PREC_PROBA;
	r += coder_uniforme(l->valeur >> l->taille, 1 << PREC_PROBA, state);
	l->valeur &= ((1 << l->taille) - 1);
      }
      r += coder_uniforme(l->valeur, 1 << l->taille, state);
    }
  }

  if (state->min == 0) // cas particulier, implique state->compteur == 0
    bwrite_bit(0, state->buffer);
  else {
    bwrite_bit(1, state->buffer);
    bwrite_bits(0, state->compteur, state->buffer); // éventuellement 0
  }
  ++r;

  if (accel) {
     // les i derniers bits redeviennent accessibles
    bwrite_decaler_fin(state->buffer, i);

    // on repositionne le pointeur juste avant la zone reservée
    bwrite_changer_position(state->buffer, state->buffer->fin - i);

    for (l = liste_todo; l != NULL; l = l->suivant)
      bwrite(l->valeur, l->taille, state->buffer);

    r += i; // i est la somme des l->taille
  }

#ifdef DEBUG
  printf("%d\n", r);
  for (l = liste_todo; l != NULL; l = l->suivant)
    printf("%d\t%d\t%u\t%u\n", l->nombre, l->taille, l->maximum, l->valeur);
#endif

  free(aux);
  liste_free(liste_todo);

  return r;
}

int dichoinv_rec(int * cw, int i, int s, int x, arith_t state, precomp_t p) {
  int l, r;

  if (i == 0)
    return 0;

  if (i > (1 << s) - i) {
    liste_inv = liste_alloc(liste_inv);
    liste_inv->nombre = i;
    liste_inv->element = cw;
    liste_inv->taille = s;
    liste_inv->pos = x;
    return dichoinv_rec(cw, (1 << s) - i, s, x, state, p);
  }

  if (i == 1) {
    liste_todo = liste_alloc(liste_todo);
    liste_todo->element = cw;
    liste_todo->nombre = 1;
    liste_todo->taille = s;
    liste_todo->valeur = 0;
    liste_todo->pos = x;
    liste_todo->maximum = 1 << s;
    return 0;
  }

  if (is_leaf(s, i)) {
    liste_todo = liste_alloc(liste_todo);
    liste_todo->element = cw;
    liste_todo->nombre = i;
    liste_todo->pos = x;
    liste_todo->maximum = p.leaf_info[s][i].maximum;
    liste_todo->taille = p.leaf_info[s][i].deadbits;
    return 0;
  }

  r = decoder(precomp_get_distrib(p, s, i), &l, state);

#ifdef DEBUG
  printf("%d = %d + %d\n", i, l, i - l);
#endif
  r += dichoinv_rec(cw, l, s - 1, x, state, p);
  r += dichoinv_rec(cw + l, i - l, s - 1, x ^ (1 << (s - 1)), state, p);

  return r;
}

int dichoinv(int *cw, arith_t state, precomp_t p) {
  int m, t, r, i, accel;
  unsigned long x;
  liste_t l;
  unsigned char c;

  m = p.m;
  t = p.t;

  liste_todo = NULL;
  liste_inv = NULL;

  r = dichoinv_rec(cw, t, m, 0, state, p);

#ifdef DEBUG
  printf("%d\n", r);
  for (l = liste_todo; l != NULL; l = l->suivant)
    printf("%d\t%d\t%u\t%d\n", l->nombre, l->taille, l->maximum, l->pos);
#endif

  // calcul du nombre i de bits réservés
  for (i = 0, l = liste_todo; l != NULL; l = l->suivant)
    i += l->taille;

  // cf. discussion dans dicho()
  accel = (bread_unlocked(state->buffer) >= i);

#ifdef DEBUG
  printf(accel ? "accel : oui\n" : "accel : non\n");
  printf("%d\t%d\n", bread_unlocked(state->buffer), i);
#endif

  if (accel)
    // les i derniers bits du buffer deviennent illisibles (-> '0')
    bread_decaler_fin(state->buffer, -i);

  for (l = liste_todo; l != NULL; l = l->suivant)
    if (l->nombre > 1) {
      r += decoder_uniforme(l->maximum, &x, state);
      l->valeur = x << l->taille;
    }

#ifdef DEBUG
  printf("%d\n", r);
#endif

  if (accel) {
    // les i derniers bits sont de nouveau lisibles
    bread_decaler_fin(state->buffer, i);

    // et on repositionne le pointeur juste avant la zone reservée
    bread_changer_position(state->buffer, state->buffer->fin - i);

    for (l = liste_todo; l != NULL; l = l->suivant)
      l->valeur ^= bread(l->taille, state->buffer);

    r += i; // i est la somme des l->taille
  }
  else {
    for (l = liste_todo; l != NULL; l = l->suivant) {
      while (l->taille > PREC_PROBA) {
	r += decoder_uniforme(1 << PREC_PROBA, &x, state);
	l->taille -= PREC_PROBA;
	l->valeur ^= x << l->taille;
      }
      r += decoder_uniforme(1 << l->taille, &x, state);
      l->valeur ^= x;
    }
  }

  // À ce stade l'état du codeur arithmétique ne changera plus. En
  // principe l'amplitude de l'intervalle [min,max[ qu'il contient est
  // entre 1/4 (exclus) et 1/2 (inclus). Il reste donc un bit "à
  // lire". Sa valeur est parfaitement déterminée :
  //  - il vaut 1 si (state->compteur == 0) et (state->min > 0)
  //  - il vaut 0 si (state->compteur > 0) ou (state->min == 0)
  // On incrémente donc r (pour retourner la bonne valeur)
  ++r;

  // Notons qu'il existe des cas dégénérés dans lesquels l'intervalle
  // [min,max[ peut avoir une amplitude supérieure à 1/2. La valeur
  // retournée sera alors trop grande. Tel qu'est écrit le programme,
  // ce n'est pas grave, car il teste seulement si la valeur retournée
  // est suffisamment grande.

  for (l = liste_todo; l != NULL; l = l->suivant) {
    cw_decoder(l->valeur, l->nombre, l->element);
    for (i = 0; i < l->nombre; ++i)
      l->element[i] ^= l->pos;
  }

#ifdef DEBUG
  printf("%d\n", r);
  for (l = liste_todo; l != NULL; l = l->suivant)
    printf("%d\t%d\t%u\t%u\t%d\n", l->nombre, l->taille, l->maximum, l->valeur, l->pos);
#endif

  for (l = liste_inv; l != NULL; l = l->suivant) {
    int j, k;
    int * cw2;
    cw2 = malloc(((1 << l->taille) - l->nombre) * sizeof (int));
    memcpy(cw2, l->element, ((1 << l->taille) - l->nombre) * sizeof (int));
    i = l->pos;
    for (j = 0, k = 0; (k < (1 << l->taille) - l->nombre) && (j < l->nombre); ++i)
      if (cw2[k] == i)
	++k;
      else {
	l->element[j] = i;
	++j;
      }
    for (; j < l->nombre; ++j, ++i)
      l->element[j] = i;
    free(cw2);
  }

#ifdef DEBUG
  for (i = 0; i < t; ++i) printf("%d\t%d\n", i, cw[i]);
#endif

  liste_free(liste_todo);
  liste_free(liste_inv);

  return r;
}

// Transformation d'une séquence binaire de longueur l en un mot de
// poids t et de longueur 2^m.  Cette fonction va lire len bits dans
// input_message à partir du start-ième bit et les transformer en un
// mot de poids constant cw (la longueur et le poids du mot sont dans
// la structure p). Si plus de l > len, les bits après le len-ième
// sont des '0'. La valeur retournée est l.

// Les bits sont numérotés du moins significatif au plus
// significatif. Par exemple le (8*i+j)-ième bit est égal à :
// (input_message[i] >> j) & 1
// Le buffer utilisé dans le codage arithmétique va lire les bits dans
// un autre ordre : les octets sont lus dans le même ordre, mais dans
// chaque octet le premier bit lu est le bit de poids fort (c'est
// nécessaire !). D'où la petite manipulation au début et à la fin
int dicho_b2cw(unsigned char * input_message, int * cw, int start, int len, int m, int t, precomp_t p) {
  int i, j, k, l, end, reduc;
  arith_t state;
  unsigned char c, d;
  int * cw2;

  if ((t != p.real_t) || (m != p.real_m)) {
    printf("inconsistent data for cw, rerun genparams\n");
    exit(0);
  }

  if (start % 8) {
    c = input_message[start / 8];
    input_message[start / 8] >>= (start % 8);
  }
  end = start + len;
  if (end % 8) {
    d = input_message[end / 8];
    input_message[end / 8] <<= (8 - (end % 8));
  }

  state = arith_init(breadinit(input_message, end));

  // la variable p contient 5 champs : distrib qui contient des
  // probabilités précalculées, et 4 entiers m, t, real_m et real_t.
  // Nous générons des mots de poids real_t et de longueur
  // 2^real_m. Le programme peut être accéléré, sans perte
  // significative d'efficacité, en générant des mots de poids t et de
  // longueur 2^m. Il manque (real_m - m) bits par position qui sont
  // placés au début du buffer, de plus si 2 * real_t > 2^m alors
  // t = 2^m - real_t

  // On saute les start premiers bits, et, éventuellement, reduc*t
  // de plus qui serviront à modifier cw à la fin.
  reduc = m - p.m;
  bread_changer_position(state->buffer, start + reduc * t);

  cw2 = malloc(p.t * sizeof (int));

  l = dichoinv(cw2, state, p);

  if (p.t == t)
    memcpy(cw, cw2, t * sizeof (int));
  else {
    k = 0;
    for (j = 0; j < cw2[0]; ++k, ++j)
      cw[k] = j;
    for (i = 1; i < p.t; ++i) {
      for (j = cw2[i - 1] + 1; j < cw2[i]; ++k, ++j)
	cw[k] = j;
    }
    for (j = cw2[p.t - 1] + 1; j < (1 << m); ++k, ++j)
      cw[k] = j;
  }
  free(cw2);

  if (reduc > 0) {
    // on revient a start puis on ajuste cw
    bread_changer_position(state->buffer, start);
    for (j = 0; j < t; ++j)
      cw[j] = (cw[j] << reduc) ^ bread(reduc, state->buffer);
    l += reduc * t;
  }

  breadclose(state->buffer);
  free(state);

  if (start % 8) {
    input_message[start / 8] = c;
  }
  if (end % 8) {
    input_message[end / 8] = d;
  }

  if (l < len)
    return -1;
  else
    return l;
}

// Transformation d'un mot de poids t et de longueur 2^m en une
// séquence binaire de longueur l.  Cette fonction va lire un mot de
// poids constant cw et écrire len bits dans output_message à partir
// du start-ième bit (la longueur et le poids du mot cw sont dans la
// structure p). Si plus de l > len, les bits à partir du len-ième
// sont ignorés. La valeur retournée est l.

// Les bits sont numérotés du moins significatif au plus
// significatif. Par exemple le (8*i+j)-ième bit est égal à :
// (output_message[i] >> j) & 1
// Le buffer utilisé dans le codage arithmétique va lire les bits dans
// un autre ordre : les octets sont lus dans le même ordre, mais dans
// chaque octet le premier bit lu est le bit de poids fort (c'est
// nécessaire !). D'où la petite manipulation au début et à la fin.
int dicho_cw2b(int * cw, unsigned char * output_message, int start, int len, int m, int t, precomp_t p) {
  int i, j, k, l, end, reduc, mask;
  arith_t state;
  bwrite_t b;
  int * cw2;
  unsigned char c, d;

  if ((t != p.real_t) || (m != p.real_m)) {
    printf("inconsistent data for cw, rerun genparams\n");
    exit(0);
  }

  if (start % 8) {
    c = output_message[start / 8] & ((1 << (start % 8)) - 1);
    output_message[start / 8] = 0;
  }
  end = start + len;

  state = arith_init(bwriteinit(output_message, end));
  // On saute les start premiers bits
  bwrite_changer_position(state->buffer, start);

  // la variable p contient 5 champs : distrib qui contient des
  // probabilités précalculées, et 4 entiers m, t, real_m et real_t.
  // Nous générons des mots de poids real_t et de longueur
  // 2^real_m. Le programme peut être accéléré, sans perte
  // significative d'efficacité, en générant des mots de poids t et de
  // longueur 2^m. Il manque (real_m - m) bits par position qui sont
  // placés au début du buffer, de plus si 2 * real_t > 2^m alors
  // t = 2^m - real_t.

  reduc = m - p.m;
  if (reduc > 0) {
    // On copie les derniers bits de chaque position dans le buffer
    mask = (1 << reduc) - 1;
    for (j = 0; j < t; ++j)
      bwrite(cw[j] & mask, reduc, state->buffer);
  }

  cw2 = malloc(p.t * sizeof (int));

  if (t == p.t) {
    for (j = 0; j < t; ++j)
      cw2[j] = cw[j] >> reduc;
  }
  else {
    k = 0;
    for (j = 0; j < (cw[0] >> reduc); ++k, ++j)
      cw2[k] = j;
    for (i = 1; i < t; ++i) {
      for (j = (cw[i - 1] >> reduc) + 1; j < (cw[i] >> reduc); ++k, ++j)
	cw2[k] = j;
    }
    for (j = (cw[t - 1] >> reduc) + 1; j < (1 << m); ++k, ++j)
      cw2[k] = j;
  }

  l = reduc * t + dicho(cw2, state, p);

  free(cw2);

  bwriteclose(state->buffer);
  free(state);

  if (start % 8) {
    output_message[start / 8] <<= (start % 8);
    output_message[start / 8] ^= c;
  }
  if (end % 8) {
    output_message[end / 8] >>= (8 - (end % 8));
  }

  if (l < len)
    return -1;
  else
    return l;
}
