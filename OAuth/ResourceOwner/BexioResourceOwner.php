<?php

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Symfony\Component\OptionsResolver\OptionsResolverInterface;

/**
 * Class BexioResourceOwner
 *
 * @author Konrad Podgórski <konrad.podgorski@ibrows.ch>
 */
class BexioResourceOwner extends GenericOAuth2ResourceOwner
{
    /**
     * {@inheritDoc}
     */
    protected function configureOptions(OptionsResolverInterface $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'authorization_url' => 'https://office.bexio.com/oauth/authorize',
            'access_token_url'  => 'https://office.bexio.com/oauth/access_token',
            'infos_url'         => 'https://office.bexio.com/api2.php/%org%',
            'use_bearer_authorization' => true,
            'csrf' => true
        ));
    }

    /**
     * {@inheritDoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = array())
    {
        if (isset($accessToken['org'])) {
            $this->options['org'] = $accessToken['org'];
        }

        $response = $this->getUserResponse();
        // there is no response because bexio does not provide infos_url
        //$response->setResponse($content->getContent());

        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    /**
     * @param string $url
     * @param array  $parameters
     *
     * @return string
     */
    protected function normalizeUrl($url, array $parameters = array())
    {
        if (isset($this->options['org'])) {
            $url = str_replace('%org%', $this->options['org'], $url);
        }

        return parent::normalizeUrl($url, $parameters);
    }
}
