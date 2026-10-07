/*
=========================================================
ANTBYTE PLATFORM
Firebase Authentication + Realtime Database
=========================================================
*/


// ======================================================
// FIREBASE CONFIGURATION
// ======================================================

const FIREBASE_API_KEY =
    "AIzaSyBdwsshU3MErA5Cgxf7ChmW4g2NGVvCMnk";

const AUTH_BASE =
    "https://identitytoolkit.googleapis.com/v1";

const REFRESH_URL =
    "https://securetoken.googleapis.com/v1/token?key=" +
    FIREBASE_API_KEY;

const DB_URL =
    "https://lectura-campus-workspace-default-rtdb.firebaseio.com";

const STORAGE_KEY =
    "antbyte_platform_data";


// ======================================================
// APPLICATION STATE
// ======================================================

const state = {

    authToken: "",
    refreshToken: "",
    uid: "",

    email: "",
    name: "",

    loggedIn: false,

    online: navigator.onLine,

    page: "store",

    items: []

};


// ======================================================
// DOM HELPERS
// ======================================================

const $ = id =>
    document.getElementById(id);


// ======================================================
// LOCAL SESSION
// ======================================================

function save() {

    localStorage.setItem(
        STORAGE_KEY,

        JSON.stringify({

            name: state.name,
            email: state.email,

            refreshToken:
                state.refreshToken,

            uid:
                state.uid

        })
    );

}


function load() {

    try {

        const data =
            JSON.parse(
                localStorage.getItem(
                    STORAGE_KEY
                ) || "null"
            );

        if (!data)
            return;

        state.name =
            data.name || "";

        state.email =
            data.email || "";

        state.refreshToken =
            data.refreshToken || "";

        state.uid =
            data.uid || "";

        state.loggedIn =
            !!(
                state.uid &&
                state.name
            );

    } catch (error) {

        console.warn(
            "Could not load AntByte session.",
            error
        );

    }

}


// ======================================================
// SECURITY / HTML ESCAPING
// ======================================================

function esc(value) {

    return String(
        value ?? ""
    ).replace(
        /[&<>"']/g,

        character => ({

            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"

        }[character])
    );

}


// ======================================================
// NOTIFICATION
// ======================================================

function notify(message) {

    let toast =
        $("toast");

    if (!toast) {

        toast =
            document.createElement(
                "div"
            );

        toast.id =
            "toast";

        toast.style.position =
            "fixed";

        toast.style.bottom =
            "25px";

        toast.style.left =
            "50%";

        toast.style.transform =
            "translateX(-50%)";

        toast.style.zIndex =
            "99999";

        toast.style.background =
            "#202a33";

        toast.style.border =
            "1px solid rgba(255,255,255,.15)";

        toast.style.color =
            "white";

        toast.style.padding =
            "14px 22px";

        toast.style.borderRadius =
            "5px";

        toast.style.boxShadow =
            "0 10px 40px rgba(0,0,0,.5)";

        document.body.appendChild(
            toast
        );

    }

    toast.textContent =
        message;

    toast.style.display =
        "block";

    clearTimeout(
        notify.timer
    );

    notify.timer =
        setTimeout(
            () => {

                toast.style.display =
                    "none";

            },
            3200
        );

}


// ======================================================
// FIREBASE AUTH API
// ======================================================

async function firebaseAuthRequest(
    path,
    body
) {

    const response =
        await fetch(
            AUTH_BASE +
            path,

            {

                method: "POST",

                headers: {

                    "Content-Type":
                        "application/json"

                },

                body:
                    JSON.stringify(body)

            }
        );


    let data = {};

    try {

        data =
            await response.json();

    } catch (error) {

        data = {};

    }


    if (
        !response.ok ||
        data.error
    ) {

        const code =
            data?.error?.message ||
            "AUTH_ERROR";


        const errorMessages = {

            EMAIL_EXISTS:
                "That email is already registered.",

            EMAIL_NOT_FOUND:
                "Incorrect email or password.",

            INVALID_PASSWORD:
                "Incorrect email or password.",

            INVALID_LOGIN_CREDENTIALS:
                "Incorrect email or password.",

            WEAK_PASSWORD:
                "Password must contain at least 6 characters.",

            INVALID_EMAIL:
                "Enter a valid email address.",

            USER_DISABLED:
                "This account has been disabled."

        };


        throw new Error(
            errorMessages[code] ||
            code
        );

    }


    return data;

}


// ======================================================
// SIGN UP
// ======================================================

async function signUp() {

    const nameInput =
        document.getElementById(
            "accountName"
        );

    const emailInput =
        document.getElementById(
            "accountEmail"
        );

    const passwordInput =
        document.getElementById(
            "accountPassword"
        );


    const name =
        nameInput?.value.trim();

    const email =
        emailInput?.value.trim();

    const password =
        passwordInput?.value;


    if (!email || !password) {

        notify(
            "Enter your email and password."
        );

        return;

    }


    if (password.length < 6) {

        notify(
            "Password must contain at least 6 characters."
        );

        return;

    }


    try {

        const data =
            await firebaseAuthRequest(

                "/accounts:signUp?key=" +
                FIREBASE_API_KEY,

                {

                    email:
                        email,

                    password:
                        password,

                    returnSecureToken:
                        true

                }

            );


        state.name =
            name ||
            email.split("@")[0];

        applyAuth(
            data
        );


        await saveProfile();


        notify(
            "AntByte account created successfully."
        );


        closeAccountModal();

    } catch (error) {

        notify(
            error.message
        );

    }

}


// ======================================================
// SIGN IN
// ======================================================

async function signIn() {

    const emailInput =
        document.getElementById(
            "accountEmail"
        );

    const passwordInput =
        document.getElementById(
            "accountPassword"
        );


    const email =
        emailInput?.value.trim();

    const password =
        passwordInput?.value;


    if (!email || !password) {

        notify(
            "Enter your email and password."
        );

        return;

    }


    try {

        const data =
            await firebaseAuthRequest(

                "/accounts:signInWithPassword?key=" +
                FIREBASE_API_KEY,

                {

                    email:
                        email,

                    password:
                        password,

                    returnSecureToken:
                        true

                }

            );


        applyAuth(
            data
        );


        await loadProfile();


        notify(
            "Signed in successfully."
        );


        closeAccountModal();

    } catch (error) {

        notify(
            error.message
        );

    }

}


// ======================================================
// APPLY AUTH SESSION
// ======================================================

function applyAuth(data) {

    state.authToken =
        data.idToken || "";

    state.refreshToken =
        data.refreshToken || "";

    state.uid =
        data.localId || "";

    state.email =
        data.email ||
        state.email;

    state.loggedIn =
        !!(
            state.authToken &&
            state.uid
        );


    if (!state.name) {

        state.name =
            state.email
                ? state.email.split("@")[0]
                : "AntByte User";

    }


    save();

    updateAccountButton();

}


// ======================================================
// REFRESH FIREBASE SESSION
// ======================================================

async function refreshSession() {

    if (!state.refreshToken)
        return;


    try {

        const response =
            await fetch(
                REFRESH_URL,

                {

                    method: "
