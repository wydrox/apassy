// https://apassy.wyderka.cc/install.sh: the installer of scripts/install.sh, copied
// at build time, so the site always serves the file of the repository.
import script from "../../../scripts/install.sh?raw";

export const GET = () => new Response(script);
