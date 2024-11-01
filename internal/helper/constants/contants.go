package constants

const (
	AUTH_JWT      = "AUTH_JWT"
	REFRESH_TOKEN = "REFRESH_TOKEN"
)

type Exchanges struct {
	Exchange map[string]Exchange
}

type Exchange struct {
	Exchange   string
	RoutingKey map[string]string
}

// Initialize exchanges dynamically
var RabbitMQMaster = Exchanges{
	Exchange: map[string]Exchange{
		"notification": {
			Exchange: "notification_exchange",
			RoutingKey: map[string]string{
				"sms":   "sms_routing_key",
				"email": "email_routing_key",
			},
		},
		"logs": {
			Exchange: "logs_exchange",
			RoutingKey: map[string]string{
				"info":  "info_routing_key",
				"error": "error_routing_key",
			},
		},
	},
}

func (e Exchanges) GetRoutingKey(exchangeName, routingKey string) (string, bool) {
	exch, exists := e.Exchange[exchangeName]
	if !exists {
		return "", false
	}
	routing, exists := exch.RoutingKey[routingKey]
	return routing, exists
}

// type Exchanges struct {
// 	Exchange Exchange
// }

// type Exchange struct {
// 	Exchange   string
// 	RoutingKey RoutingKey
// }

// type RoutingKey struct {
// 	Sms   string
// 	Email string
// }

// var (
// 	RabbitMQMaster = Exchanges{
// 		Exchange: Exchange{
// 			Exchange: "notification",
// 			RoutingKey: RoutingKey{
// 				Sms:   "sms",
// 				Email: "email",
// 			},
// 		},
// 	}
// )
