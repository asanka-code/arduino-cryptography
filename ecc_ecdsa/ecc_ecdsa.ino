#include <uECC.h>
#include <uECC_vli.h>
#include <types.h>

extern "C" {


//static
int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"

void setup() {
  Serial.begin(115200);
  Serial.print("Testing ecc\n");
  uECC_set_rng(&RNG);
}

void loop() {
  const struct uECC_Curve_t * curve = uECC_secp160r1();
  //const struct uECC_Curve_t * curve = uECC_secp192r1();
  //const struct uECC_Curve_t * curve = uECC_secp224r1();
  //const struct uECC_Curve_t * curve = uECC_secp256r1();
  //const struct uECC_Curve_t * curve = uECC_secp256k1();
  
  uint8_t private0[32] = {0};
  uint8_t public0[64] = {0};
  uint8_t hash[32] = {0};
  uint8_t sig[64] = {0};

  //unsigned long a = millis();
  uECC_make_key(public0, private0, curve);
  //unsigned long b = millis();
  //Serial.print("Made keys in "); Serial.println(b-a);
  int pri_size = uECC_curve_private_key_size(curve);
  int pub_size = uECC_curve_public_key_size(curve);
  Serial.print("pri key size = "); Serial.println(pri_size);
  Serial.print("pub key size = "); Serial.println(pub_size);

  memcpy(hash, public0, sizeof(hash));

  if (!uECC_sign(private0, hash, sizeof(hash), sig, curve)) {
    Serial.print("uECC_sign() failed\n");
    //return 1;
  } else {
    Serial.print("uECC_sign() successful\n");
  }

  if (!uECC_verify(public0, hash, sizeof(hash), sig, curve)) {
    Serial.print("uECC_verify() failed\n");
    //return 1;
  } else {
    Serial.print("uECC_verify() successful\n");  
  }
}
