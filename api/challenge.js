// Vérification de domaine pour l'annuaire d'apps ChatGPT (à remplir plus tard avec le jeton fourni par OpenAI)
module.exports = (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.status(200).send(process.env.OPENAI_APPS_CHALLENGE || '');
};
