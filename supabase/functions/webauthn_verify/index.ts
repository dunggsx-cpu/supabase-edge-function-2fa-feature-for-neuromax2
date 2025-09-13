import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { verifyRegistrationResponse } from "npm:@simplewebauthn/server";
import { isoBase64URL } from "npm:@simplewebauthn/server/helpers";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Credentials": "true",
};
const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
  {
    auth: {
      persistSession: false,
    },
  }
);
serve(async (req) => {
  if (req.method === "OPTIONS")
    return new Response(null, {
      headers: corsHeaders,
    });
  if (req.method !== "POST")
    return new Response("Method not allowed", {
      status: 405,
      headers: corsHeaders,
    });
  try {
    const { user_id, attResp } = await req.json();
    const { data: sec } = await supabase
      .from("user_security")
      .select("*")
      .eq("user_id", user_id)
      .single();
    if (!sec?.current_challenge) {
      return new Response(
        JSON.stringify({
          error: "No active challenge",
        }),
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }
    const origin = req.headers.get("origin") ?? "";
    let rpID;
    try {
      const url = new URL(origin);
      rpID = url.hostname;
      if (
        rpID === "localhost" &&
        (url.port === "3000" || url.port === "8000")
      ) {
        rpID = "localhost";
      }
    } catch {
      rpID = "localhost";
    }
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: sec.current_challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });
    if (!verification.verified || !verification.registrationInfo) {
      return new Response(
        JSON.stringify({
          error: "Registration verification failed",
        }),
        {
          status: 400,
          headers: corsHeaders,
        }
      );
    }
    const { id, publicKey, counter } = verification.registrationInfo.credential;
    const credentialID_b64 = id;
    const publicKey_b64 = isoBase64URL.fromBuffer(publicKey);
    await supabase
      .from("user_security")
      .update({
        webauthn_credentials: [
          {
            credentialID: credentialID_b64,
            credentialPublicKey: publicKey_b64,
            counter,
          },
        ],
        webauthn_enabled: true,
        current_challenge: null,
        enable_login: true,
      })
      .eq("user_id", user_id);
    return new Response(
      JSON.stringify({
        ok: true,
      }),
      {
        status: 200,
        headers: corsHeaders,
      }
    );
  } catch (err) {
    console.error("[WEBAUTHN_VERIFY_ERROR]", err);
    return new Response(
      JSON.stringify({
        error: err.message,
      }),
      {
        status: 500,
        headers: corsHeaders,
      }
    );
  }
});
