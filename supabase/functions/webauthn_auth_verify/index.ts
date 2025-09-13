// supabase/functions/webauthn_auth_verify/index.ts
import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} from "npm:@simplewebauthn/server";
import { isoBase64URL } from "npm:@simplewebauthn/server/helpers";
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
const logStep = (step, details) => {
  const detailsStr = details ? ` - ${JSON.stringify(details)}` : "";
  console.log(`[WEBAUTHN_VERIFY] ${step}${detailsStr}`);
};
serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: corsHeaders,
    });
  }
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: corsHeaders,
    });
  }
  try {
    const { action, user_id, authResp } = await req.json();
    const { data: sec, error: secError } = await supabase
      .from("user_security")
      .select("*")
      .eq("user_id", user_id)
      .single();
    if (secError || !sec) {
      logStep("User not found", {
        error: secError?.message,
      });
      return new Response(
        JSON.stringify({
          error: "User not found",
        }),
        {
          status: 404,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
    let origin = req.headers.get("origin") ?? "";
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
    if (action === "generate-options") {
      if (!sec.webauthn_credentials || sec.webauthn_credentials.length === 0) {
        return new Response(
          JSON.stringify({
            error: "User has no WebAuthn credentials",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      const allowCredentials = sec.webauthn_credentials.map((c) => ({
        id: c.credentialID,
        type: "public-key",
      }));
      const options = await generateAuthenticationOptions({
        rpID: rpID,
        userVerification: "preferred",
        allowCredentials,
      });
      await supabase
        .from("user_security")
        .update({
          current_challenge: options.challenge,
        })
        .eq("user_id", user_id);
      // logStep("Challenge saved to DB");
      return new Response(JSON.stringify(options), {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      });
    }
    if (action === "verify") {
      if (!authResp) {
        return new Response(
          JSON.stringify({
            error: "Missing WebAuthn response",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      if (!sec.current_challenge) {
        return new Response(
          JSON.stringify({
            error: "No active challenge",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      if (!sec.webauthn_enabled) {
        return new Response(
          JSON.stringify({
            error: "WebAuthn not enabled",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      const dbCred = sec.webauthn_credentials.find(
        (c) =>
          c.credentialID === authResp.rawId || c.credentialID === authResp.id
      );
      if (!dbCred) {
        return new Response(
          JSON.stringify({
            error: "Credential not found",
          }),
          {
            status: 404,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      const verification = await verifyAuthenticationResponse({
        response: authResp,
        expectedChallenge: sec.current_challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: isoBase64URL.toBuffer(dbCred.credentialID),
          publicKey: isoBase64URL.toBuffer(dbCred.credentialPublicKey),
          counter: dbCred.counter,
          transports: dbCred.transports || ["internal"],
        },
      });
      if (!verification.verified) {
        return new Response(
          JSON.stringify({
            error: "Authentication verification failed",
          }),
          {
            status: 400,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/json",
            },
          }
        );
      }
      const updatedCredentials = sec.webauthn_credentials.map((cred) =>
        cred.credentialID === dbCred.credentialID
          ? {
              ...cred,
              counter: verification.authenticationInfo.newCounter,
            }
          : cred
      );
      await supabase
        .from("user_security")
        .update({
          current_challenge: null,
          webauthn_credentials: updatedCredentials,
          enable_login: true,
        })
        .eq("user_id", user_id);
      return new Response(
        JSON.stringify({
          ok: true,
          msg: "WebAuthn verified successfully",
        }),
        {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
    return new Response(
      JSON.stringify({
        error: "Invalid action. Use 'generate-options' or 'verify'",
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  } catch (err) {
    logStep("ERROR", {
      error: err.message ?? String(err),
    });
    return new Response(
      JSON.stringify({
        error: "Server error",
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
});
