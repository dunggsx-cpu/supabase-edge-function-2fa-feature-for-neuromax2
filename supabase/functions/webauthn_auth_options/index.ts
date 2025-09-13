// supabase/functions/webauthn_auth_options/index.ts
import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { generateAuthenticationOptions } from "npm:@simplewebauthn/server";
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
const logStep = (step, details) => {
  const detailsStr = details ? ` - ${JSON.stringify(details)}` : "";
  console.log(`[WEBAUTHN_AUTH_OPTIONS] ${step}${detailsStr}`);
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
    const { user_id } = await req.json();
    if (!user_id) {
      return new Response(
        JSON.stringify({
          error: "Missing user_id",
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
    const { data: sec, error: secError } = await supabase
      .from("user_security")
      .select("*")
      .eq("user_id", user_id)
      .single();
    if (secError || !sec?.webauthn_credentials?.length) {
      logStep("No credentials found", {
        error: secError?.message,
      });
      return new Response(
        JSON.stringify({
          error: "No WebAuthn credentials found",
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
    const allowCredentials = sec.webauthn_credentials.map((cred) => ({
      id: cred.credentialID,
      type: "public-key",
    }));
    logStep("Generating authentication options", {
      rpID,
      allowCredentialsCount: allowCredentials.length,
    });
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: "preferred",
    });
    await supabase
      .from("user_security")
      .update({
        current_challenge: options.challenge,
      })
      .eq("user_id", user_id);
    return new Response(JSON.stringify(options), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
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
